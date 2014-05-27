#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <strings.h>
#include <err.h>
#include <fcntl.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/cpuset.h>
#include <sys/sysctl.h>

#include <netinet/in.h>

#include <pthread.h>
#include <pthread_np.h>

struct thr_setup {
	int s;
	int rss_bucket;
	int tid;
	int cpuid;
	pthread_t thr;
};

/* XXX until these are in freebsd-head */
#define	IP_BINDMULTI 25
#define IP_RSS_LISTEN_BUCKET 26
#define IP_RSSCPUID 71
#define IP_RSSBUCKETID 72

void *
srv_thr(void *s)
{
	struct thr_setup *th = s;
	int opt;
	int retval;
	socklen_t optlen;
	struct sockaddr_in sa;
	int fd;
	cpuset_t cp;

	/* Pin */
	CPU_ZERO(&cp);
	CPU_SET(th->cpuid, &cp);

	if (pthread_setaffinity_np(th->thr, sizeof(cpuset_t), &cp) != 0)
		warn("pthread_setaffinity_np (id %d)", th->tid);

	th->s = socket(PF_INET, SOCK_STREAM, 0);
	if (th->s < 0) {
		warn("%s: socket", __func__);
		return (NULL);
	}

	/* Set bindmulti */
	opt = 1;
	optlen = sizeof(opt);
	retval = setsockopt(th->s, IPPROTO_IP,
	    IP_BINDMULTI,
	    &opt,
	    optlen);
	if (retval < 0) {
		warn("%s: setsockopt(IP_BINDMULTI)", __func__);
		close(th->s);
		return (NULL);
	}

	/* Set RSS bucket */
	//printf("thr %d: bucket %d\n", th->tid, th->rss_bucket);
	opt = th->rss_bucket;
	optlen = sizeof(opt);
	retval = setsockopt(th->s, IPPROTO_IP,
	    IP_RSS_LISTEN_BUCKET,
	    &opt,
	    optlen);
	if (retval < 0) {
		warn("%s: setsockopt(IP_RSS_LISTEN_BUCKET)", __func__);
		close(th->s);
		return (NULL);
	}


	/* reuseaddr/reuseport */
	opt = 1;
	optlen = sizeof(opt);
	retval = setsockopt(th->s, SOL_SOCKET,
	    SO_REUSEPORT,
	    &opt,
	    optlen);
	if (retval < 0) {
		warn("%s: setsockopt(SO_REUSEPORT)", __func__);
		close(th->s);
		return (NULL);
	}

	/* Bind */
	bzero(&sa, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(6969);
	sa.sin_addr.s_addr = INADDR_ANY;

	retval = bind(th->s, (struct sockaddr *) &sa, sizeof(sa));
	if (retval < 0) {
		warn("%s: bind()", __func__);
		close(th->s);
		return (NULL);
	}

	/* Listen */
	retval = listen(th->s, -1);
	if (retval < 0) {
		warn("%s: listen()", __func__);
		close(th->s);
		return (NULL);
	}

	/* Accept loop */
	for (;;) {
		uint32_t flowid = 0, rsscpu = 0, rssbucket = 0;

		optlen = sizeof(sa);
		fd = accept(th->s, (struct sockaddr *) &sa,
		    &optlen);
		if (fd < 0) {
			warn("%s: accept", __func__);
			continue;
		}

		optlen = sizeof(uint32_t);
		retval = getsockopt(fd, IPPROTO_IP, IP_FLOWID, &flowid, &optlen);

		optlen = sizeof(uint32_t);
		retval = getsockopt(fd, IPPROTO_IP, IP_RSSCPUID, &rsscpu, &optlen);

		optlen = sizeof(uint32_t);
		retval = getsockopt(fd, IPPROTO_IP, IP_RSSBUCKETID, &rssbucket, &optlen);

		printf("%s: thr=%d, flowid=0x%08x, rsscpu=%d, rssbucket=%d\n",
		    __func__,
		    th->tid,
		    flowid, rsscpu, rssbucket);
		write(fd, "hello, world!\n", 14);
		close(fd);
	}

	return (NULL);
}

static int
rss_getsysctlint(const char *s)
{
	int val, retval;
	size_t rlen;

	rlen = sizeof(int);
	retval = sysctlbyname(s, &val, &rlen, NULL, 0);
	if (retval < 0) {
		warn("sysctlbyname (%s)", s);
		return (-1);
	}

	return (val);
}

static int
rss_getbucketmap(int *bucket_map, int nbuckets)
{
	/* XXX I'm lazy; so static string it is */
	char bstr[2048];
	int retval, i;
	size_t rlen;
	char *s, *ss;
	int r, b, c;

	/* Paranoia */
	memset(bstr, '\0', sizeof(bstr));

	rlen = sizeof(bstr) - 1;
	retval = sysctlbyname("net.inet.rss.bucket_mapping", bstr, &rlen, NULL, 0);
	if (retval < 0) {
		warn("sysctlbyname (net.inet.rss.bucket_mapping)");
		return (-1);
	}

	ss = bstr;
	while ((s =strsep(&ss, " ")) != NULL) {
		r = sscanf(s, "%d:%d", &b, &c);
		if (r != 2) {
			fprintf(stderr, "%s: string (%s) not parsable\n",
			    __func__,
			    s);
			return (-1);
		}
		if (b > nbuckets) {
			fprintf(stderr, "%s: bucket %d > nbuckets %d\n",
			    __func__,
			    b,
			    nbuckets);
			return (-1);
		}
		/* XXX no maxcpu check */
		bucket_map[b] = c;
	}
	return (0);
}

int
main(int argc, char *argv[])
{
	int i;
	struct thr_setup *ts;
	int ncpu;
	int nbuckets;
	int base_cpu;
	int *bucket_map;

	ncpu = rss_getsysctlint("net.inet.rss.ncpus");
	if (ncpu < 0) {
		fprintf(stderr, "Couldn't read net.inet.rss.ncpus\n");
		exit(127);
	}

	nbuckets = rss_getsysctlint("net.inet.rss.buckets");
	if (nbuckets < 0) {
		fprintf(stderr, "Couldn't read net.inet.rss.buckets\n");
		exit(127);
	}

	base_cpu = rss_getsysctlint("net.inet.rss.basecpu");
	if (base_cpu < 0) {
		fprintf(stderr, "Couldn't read net.inet.rss.basecpu\n");
		exit(127);
	}

	/*
	 * XXX for now this isn't needed - the bucket mapping will
	 * give us the explicit cpuid to use.
	 */

	/* Allocate enough threads - one per bucket */
	ts = calloc(nbuckets, sizeof(*ts));
	if (ts == NULL)
		err(127, "calloc");

	/* And the bucket map */
	bucket_map = calloc(nbuckets, sizeof(int));
	if (bucket_map == NULL)
		err(127, "calloc");

	if (rss_getbucketmap(bucket_map, nbuckets) < 0) {
		fprintf(stderr, "Couldn't read net.inet.rss.bucket_mapping");
		exit(127);
	}

	for (i = 0; i < nbuckets; i++) {
		ts[i].tid = i;
		ts[i].rss_bucket = i;
		ts[i].cpuid = bucket_map[i];
		printf("starting: tid=%d, rss_bucket=%d, cpuid=%d\n",
		    ts[i].tid,
		    ts[i].rss_bucket,
		    ts[i].cpuid);
		(void) pthread_create(&ts[i].thr, NULL, srv_thr, &ts[i]);
	}

	/* Wait */
	for (i = 0; i < nbuckets; i++) {
		(void) pthread_join(ts[i].thr, NULL);
	}

	exit(0);
}
