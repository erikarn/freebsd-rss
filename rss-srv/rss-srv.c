#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <strings.h>
#include <err.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/cpuset.h>

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

	printf("%s: thread id %d -> CPU %d\n", __func__, th->tid, th->cpuid);

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
	printf("thr %d: bucket %d\n", th->tid, th->rss_bucket);
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

int
main(int argc, char *argv[])
{
	int i;
	struct thr_setup ts[8];
	int ncpu = 4;		/* XXX hard-coded for now */
	int nbuckets = 8;	/* XXX hard-coded for now */

	bzero(ts, sizeof(ts));
	for (i = 0; i < nbuckets; i++) {
		ts[i].tid = i;
		ts[i].rss_bucket = i;
		/* XXX TODO: need to ask RSS for the bucket -> cpuid matching */
		ts[i].cpuid = i % ncpu;
		(void) pthread_create(&ts[i].thr, NULL, srv_thr, &ts[i]);
	}

	/* Wait */
	for (i = 0; i < nbuckets; i++) {
		(void) pthread_join(ts[i].thr, NULL);
	}

	exit(0);
}
