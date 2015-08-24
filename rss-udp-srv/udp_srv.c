#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <fcntl.h>
#include <signal.h>

#include <pthread.h>
#include <pthread_np.h>

#include <sys/types.h>
#include <sys/param.h>
#include <sys/cpuset.h>
#include <sys/socket.h>
#include <sys/errno.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <event2/event.h>
#include <event2/thread.h>
#include <event2/util.h>

#include "librss.h"

struct udp_srv_thread {
	pthread_t thr;
	int tid;
	int rss_bucket;
	int cpuid;
	int s4, s6;
	struct in_addr v4_listen_addr;
	int v4_listen_port;
	struct in6_addr v6_listen_addr;
	int v6_listen_port;
	int do_response;
	uint64_t recv_pkts;
	uint64_t sent_pkts;
	struct event_base *b;
	struct event *ev_timer;
	struct event *ev_read, *ev_write;
	struct event *ev_read6, *ev_write6;
};

static int
thr_sock_set_reuseaddr(int fd, int reuse_addr)
{
	int opt;
	socklen_t optlen;
	int retval;

	/* reuseaddr/reuseport */
	opt = reuse_addr;
	optlen = sizeof(opt);
	retval = setsockopt(fd, SOL_SOCKET,
	    SO_REUSEPORT,
	    &opt,
	    optlen);
	if (retval < 0) {
		warn("%s: setsockopt(SO_REUSEPORT)", __func__);
		return (-1);
	}
	return (0);
}

#if 0
        /* reuseaddr/reuseport */
        opt = 1;
        optlen = sizeof(opt);
        retval = setsockopt(th->s, SOL_SOCKET,
            SO_REUSEADDR,
            &opt,
            optlen);
        if (retval < 0) {
                warn("%s: setsockopt(SO_REUSEPORT)", __func__);
                close(th->s);
                return (NULL);
        }
#endif

/*
 * Setup the RSS state for a listen socket.
 *
 * Call after socket creation, before bind() and listen().
 */
static int
thr_rss_udp_listen_sock_setup(int fd, int af_family, int rss_bucket)
{

	if (rss_sock_set_bindmulti(fd, af_family, 1) < 0) {
		return (-1);
	}

	if (rss_sock_set_rss_bucket(fd, af_family, rss_bucket) < 0) {
		return (-1);
	}

#if 0
	if (rss_sock_set_recvrss(fd, af_family, rss_bucket) < 0) {
		return (-1);
	}
#endif

	if (thr_sock_set_reuseaddr(fd, 1) < 0) {
		return (-1);
	}

	return (0);
}

/*
 * IPv4 RSS listen socket creation - ipv4.
 */
static int
thr_rss_listen_udp_sock_create_ipv4(int rss_bucket,
    struct in_addr lcl_addr, int lcl_port)
{
	int fd;
	struct sockaddr_in sa4;
	int opt;
	int retval;

	/* IPv4 UDP */
	fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		warn("%s: socket()", __func__);
		goto error;
	}

	if (thr_rss_udp_listen_sock_setup(fd, AF_INET, rss_bucket) < 0) {
		goto error;
	}

	/* Bind */
	bzero(&sa4, sizeof(sa4));
	sa4.sin_family = AF_INET;
	sa4.sin_port = htons(lcl_port);
	sa4.sin_addr = lcl_addr;

	retval = bind(fd, (struct sockaddr *) &sa4, sizeof(sa4));
	if (retval < 0) {
		warn("%s: bind()", __func__);
		goto error;
	}

	/* Dont block */
	if ((opt = fcntl(fd, F_GETFL, 0)) < 0
	    || fcntl(fd, F_SETFL, opt | O_NONBLOCK) < 0) {
		warn("%s: fcntl(O_NONBLOCK)\n", __func__);
		goto error;
	}

	/* Done */
	return (fd);
error:
	close(fd);
	return (-1);
}

/*
 * IPv6 RSS listen socket creation.
 */
static int
thr_rss_listen_sock_create_ipv6(int rss_bucket, struct in6_addr lcl_addr,
    int lcl_port)
{
	int fd;
	struct sockaddr_in6 sa6;
	int opt;
	int retval;

	/* IPv6 */
	fd = socket(PF_INET6, SOCK_DGRAM, 0);
	if (fd < 0) {
		warn("%s: socket()", __func__);
		goto error;
	}

	if (thr_rss_udp_listen_sock_setup(fd, AF_INET6, rss_bucket) < 0) {
		goto error;
	}

	/* Bind */
	bzero(&sa6, sizeof(sa6));
	sa6.sin6_family = AF_INET6;
	sa6.sin6_port = htons(lcl_port);
	sa6.sin6_addr = lcl_addr;

	retval = bind(fd, (struct sockaddr *) &sa6, sizeof(sa6));
	if (retval < 0) {
		warn("%s: bind()", __func__);
		goto error;
	}

	/* Dont block */
	if ((opt = fcntl(fd, F_GETFL, 0)) < 0
	    || fcntl(fd, F_SETFL, opt | O_NONBLOCK) < 0) {
		warn("%s: fcntl(O_NONBLOCK)\n", __func__);
		goto error;
	}

	/* Done */
	return (fd);
error:
	close(fd);
	return (-1);
}

static void
thr_parse_msghdr(struct msghdr *m)
{
	const struct cmsghdr *c;
	uint32_t flowid;
	uint32_t flowtype;
	uint32_t flow_rssbucket;

	for (c = CMSG_FIRSTHDR(m); c != NULL; c = CMSG_NXTHDR(m, c)) {
#if 0
		printf("  msghdr level: %d\n", c->cmsg_level);
		printf("  msghdr type: %d\n", c->cmsg_type);
		printf("  msghdr len: %d\n", c->cmsg_len);
#endif
		if (c->cmsg_level != IPPROTO_IP)
			continue;
		switch (c->cmsg_type) {
			case IP_FLOWID:
				flowid = *(uint32_t *) CMSG_DATA(c);
				break;
			case IP_FLOWTYPE:
				flowtype = *(uint32_t *) CMSG_DATA(c);
				break;
			case IP_RSSBUCKETID:
				flow_rssbucket = *(uint32_t *) CMSG_DATA(c);
				break;
		}
	}
#if 0
	printf("  flowid=0x%08x; flowtype=%d; bucket=%d\n", flowid, flowtype, flow_rssbucket);
#endif
}

static void
thr_ev_timer(int fd, short what, void *arg)
{
	struct udp_srv_thread *th = arg;
	struct timeval tv;

	if (th->recv_pkts != 0 || th->sent_pkts != 0) {
		printf("%s: thr=%d, pkts_received=%llu, packets_sent=%llu\n",
		    __func__,
		    th->rss_bucket,
		    (unsigned long long) th->recv_pkts,
		    (unsigned long long) th->sent_pkts);
	}

	th->recv_pkts = 0;
	th->sent_pkts = 0;

	tv.tv_sec = 1;
	tv.tv_usec = 0;
	evtimer_add(th->ev_timer, &tv);
}


static void
thr_udp_ev_read(int fd, short what, void *arg)
{
	struct udp_srv_thread *th = arg;
	/* XXX should be thread-local, and a larger buffer, and likely a queue .. */
	char buf[2048];
	ssize_t ret;
	int i = 0;
	struct sockaddr_in sin;
	socklen_t sin_len;

#if 0
	/* for the msghdr contents */
	struct msghdr m;
	char msgbuf[2048];
	int msglen;

	struct iovec iov[1];
#endif

	/* Loop read UDP frames until EWOULDBLOCK or 1024 frames */
	while (i < 10240) {

#if 0
		iov[0].iov_base = buf;
		iov[0].iov_len = 2048;

		m.msg_name = NULL;
		m.msg_namelen = 0;
		m.msg_iov = iov;
		m.msg_iovlen = 1;
		m.msg_control = &msgbuf;
		m.msg_controllen = 2048;
		m.msg_flags = 0;

		ret = recvmsg(fd, &m, 0);
#endif
		sin_len = sizeof(sin);
		ret = recvfrom(fd, buf, 2048, MSG_DONTWAIT,
		    (struct sockaddr *) &sin,
		    &sin_len);

		if (ret <= 0) {
			if (errno != EWOULDBLOCK)
				warn("%s: recv", __func__);
			break;
		}
#if 0
		printf("  recv: len=%d, controllen=%d\n",
		    (int) ret,
		    (int) m.msg_controllen);
		thr_parse_msghdr(&m);
#endif
		i++;
		th->recv_pkts++;

		if (th->do_response) {
#if 1
			ret = sendto(fd, buf, ret, 0,
			    (struct sockaddr *) &sin,
			    sin_len);
			if (ret > 0) {
				th->sent_pkts++;
			}
		}
#endif
	}
#if 0
	fprintf(stderr, "%s [%p] [%d]: finished; %d frames received\n", __func__, arg, th->rss_bucket, i);
#endif
}

static void
thr_udp_ev_read6(int fd, short what, void *arg)
{
	thr_udp_ev_read(fd, what, arg);
}

static void *
thr_udp_srv_init(void *arg)
{
	struct udp_srv_thread *th = arg;
	int opt;
	socklen_t optlen;
	cpuset_t cp;
	int retval;
	char buf[128];
	struct timeval tv;

	/* thread pin for RSS */
	CPU_ZERO(&cp);
	CPU_SET(th->cpuid, &cp);

	if (pthread_setaffinity_np(th->thr, sizeof(cpuset_t), &cp) != 0)
		warn("pthread_setaffinity_np (id %d)", th->tid);

	printf("[%d] th=%p\n", th->tid, th);
	snprintf(buf, 128, "(bucket %d)", th->rss_bucket);
	(void) pthread_set_name_np(th->thr, buf);

	th->b = event_base_new();
	th->s4 = -1;
	th->s6 = -1;

	/* IPv4 socket */
	th->s4 = thr_rss_listen_udp_sock_create_ipv4(th->rss_bucket,
	    th->v4_listen_addr, th->v4_listen_port);
	if (th->s4 < 0) {
		fprintf(stderr, "%s: ipv4 listen socket creation failed!\n", __func__);
	}

	/* IPv6 socket */
	th->s6 = thr_rss_listen_sock_create_ipv6(th->rss_bucket,
	    th->v6_listen_addr, th->v6_listen_port);
	if (th->s6 < 0) {
		fprintf(stderr, "%s: ipv6 listen socket creation failed!\n", __func__);
	}

	th->ev_timer = evtimer_new(th->b, thr_ev_timer, th);
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	evtimer_add(th->ev_timer, &tv);

	/* Create read and write readiness events */
	th->ev_read = event_new(th->b, th->s4, EV_READ | EV_PERSIST,
	    thr_udp_ev_read, th);
	event_add(th->ev_read, NULL);

	th->ev_read6 = event_new(th->b, th->s6, EV_READ | EV_PERSIST,
	    thr_udp_ev_read6, th);
	event_add(th->ev_read6, NULL);

	/* Dispatch loop */
	for (;;) {
		int ret;
		ret = event_base_dispatch(th->b);
		printf("%s [%d]: event_base_dispatch() returned %d\n", __func__, th->tid, ret);
	}

finish:
	if (th->s4 != -1)
		close(th->s4);
	if (th->s6 != -1)
		close(th->s6);
	/* event_del? */
	if (th->ev_read)
		event_free(th->ev_read);
	printf("%s [%d]: done\n", __func__, th->tid);
	return (NULL);
}

int
main(int argc, char *argv[])
{
	int i;
	struct udp_srv_thread *th;
	int ncpu;
	int nbuckets;
	int base_cpu;
	int *bucket_map;
	struct sigaction sa;
	struct in_addr lcl_addr;
	struct in6_addr lcl6_addr;
	int do_response;

	if (argc < 3) {
		printf("Usage: %s <response> <ipv4 lcl address>\n", argv[0]);
		printf("    response: 1 if each RX packet generates a TX response, else 0\n");
		printf("    ipv4 lcl address: IPv4 local address to bind to\n");
		exit(1);
	}

	lcl_addr.s_addr = INADDR_ANY;
	lcl6_addr = in6addr_any;
	do_response = atoi(argv[1]);
	(void) inet_aton(argv[2], &lcl_addr);

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
	th = calloc(nbuckets, sizeof(*th));
	if (th == NULL)
		err(127, "calloc");

	/* And the bucket map */
	bucket_map = calloc(nbuckets, sizeof(int));
	if (bucket_map == NULL)
		err(127, "calloc");

	if (rss_getbucketmap(bucket_map, nbuckets) < 0) {
		fprintf(stderr, "Couldn't read net.inet.rss.bucket_mapping");
		exit(127);
	}

//	event_enable_debug_mode();
	evthread_use_pthreads();
//	evthread_enable_lock_debugging();

	/* Disable SIGPIPE */
	sa.sa_handler = SIG_IGN;
	sa.sa_flags = 0;
	if (sigemptyset(&sa.sa_mask) == -1 || sigaction(SIGPIPE, &sa, 0) == -1)
		perror("failed to ignore SIGPIPE; sigaction");

	for (i = 0; i < nbuckets; i++) {
		th[i].tid = i;
		th[i].rss_bucket = i;
		th[i].cpuid = bucket_map[i];
		th[i].v4_listen_addr = lcl_addr;
		th[i].v4_listen_port = 8080;
		th[i].v6_listen_addr = lcl6_addr;
		th[i].v6_listen_port = 8080;
		th[i].do_response = do_response;
		printf("starting: tid=%d, rss_bucket=%d, cpuid=%d\n",
		    th[i].tid,
		    th[i].rss_bucket,
		    th[i].cpuid);
		(void) pthread_create(&th[i].thr, NULL, thr_udp_srv_init, &th[i]);
	}

	/* Wait */
	for (i = 0; i < nbuckets; i++) {
		(void) pthread_join(th[i].thr, NULL);
	}

	exit(0);
}
