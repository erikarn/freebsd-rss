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
	int tid;
	int cpuid;
	pthread_t thr;
	uint64_t nrx;
	uint64_t old_nrx;
};

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

#if 0
	/* Pin */
	CPU_ZERO(&cp);
	CPU_SET(th->cpuid, &cp);
	if (pthread_setaffinity_np(th->thr, sizeof(cpuset_t), &cp) != 0)
		warn("pthread_setaffinity_np (id %d)", th->tid);
#endif

	th->s = socket(PF_INET, SOCK_DGRAM, 0);
	if (th->s < 0) {
		warn("%s: socket", __func__);
		return (NULL);
	}

	/* reuseaddr/reuseport */
	opt = 1;
	optlen = sizeof(opt);
	retval = setsockopt(th->s, SOL_SOCKET,
	    SO_REUSEPORT_LB,
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

#if 0
	/* Listen */
	retval = listen(th->s, -1);
	if (retval < 0) {
		warn("%s: listen()", __func__);
		close(th->s);
		return (NULL);
	}
#endif

	/* Accept loop */
	for (;;) {
		int len;
		char buf[1024];

		len = recv(th->s, buf, sizeof(buf), 0);
		if (len < 0) {
			warn("%s: len", __func__);
			continue;
		}

		th->nrx++;
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

	// For now, one per CPU (assuming of course they're all the same type, etc)
	ncpu = rss_getsysctlint("hw.ncpu");
	if (ncpu < 0) {
		fprintf(stderr, "Couldn't read hw.ncpu\n");
		exit(127);
	}
	ncpu = 4;
	//ncpu = 1;
	nbuckets = ncpu;

	/*
	 * XXX for now this isn't needed - the bucket mapping will
	 * give us the explicit cpuid to use.
	 */

	/* Allocate enough threads - one per bucket */
	ts = calloc(nbuckets, sizeof(*ts));
	if (ts == NULL)
		err(127, "calloc");

	for (i = 0; i < nbuckets; i++) {
		ts[i].tid = i;
		ts[i].cpuid = (i % ncpu);
		printf("starting: tid=%d, cpuid=%d\n",
		    ts[i].tid,
		    ts[i].cpuid);
		(void) pthread_create(&ts[i].thr, NULL, srv_thr, &ts[i]);
	}

	while (1) {
		uint64_t tot_diff, tot;
		sleep(1);
		printf("Stats: ");
		tot_diff = 0; tot = 0;
		for (i = 0; i < nbuckets; i++) {
			uint64_t diff = ts[i].nrx - ts[i].old_nrx;
			// Ew, reaching into that threads memory...
			ts[i].old_nrx = ts[i].nrx;

			printf("%d: %lu (%lu) ", i, ts[i].nrx, diff);
			tot_diff += diff;
		}
		printf(" [%lu]\n", tot_diff);
	}

	/* Wait */
	for (i = 0; i < nbuckets; i++) {
		(void) pthread_join(ts[i].thr, NULL);
	}

	exit(0);
}
