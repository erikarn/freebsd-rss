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
#include <sys/tree.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <event2/event.h>
#include <event2/thread.h>
#include <event2/util.h>

#include "librss.h"

static int debug = 0;

struct flow {
	RB_ENTRY(flow) link;
	uint32_t flowid;
	uint32_t flowtype;
	uint32_t flow_rssbucket;
	uint64_t count;
	uint64_t prev_count;
};

static int flow_cmp(struct flow *a, struct flow *b);

RB_HEAD(flow_tree, flow);
RB_PROTOTYPE_STATIC(flow_tree, flow, link, flow_cmp);
RB_GENERATE_STATIC(flow_tree, flow, link, flow_cmp);

struct udp_srv_thread {
	pthread_t thr;
	int tid;
	int rss_bucket;
	cpuset_t cs;
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
	struct flow_tree flow_root;
};

static struct udp_srv_thread *threads;
static struct flow_tree flow_root;

static int
flow_cmp(struct flow *a, struct flow *b)
{
	if (a->flowid != b->flowid)
		return (a->flowid - b->flowid);

	if (a->flowtype != b->flowtype)
		return (a->flowtype - b->flowtype);

	return (a->flow_rssbucket - b->flow_rssbucket);
}

static void
flow_dump(int signo)
{
	struct udp_srv_thread *th = threads;
	struct rss_config *rc;
	struct flow *fp, *nfp;
	int count, i;

	rc = rss_config_get();

	for (i = 0; i < rc->rss_nbuckets; i++) {
		RB_FOREACH(fp, flow_tree, &th[i].flow_root) {
			nfp = RB_FIND(flow_tree, &flow_root, fp);
			if (nfp == NULL) {
				nfp = malloc(sizeof(*nfp));
				if (nfp == NULL) {
					warn("%s: malloc", __func__);
					continue;
				}

				nfp->flowid = fp->flowid;
				nfp->flowtype = fp->flowtype;
				nfp->flow_rssbucket = fp->flow_rssbucket;
				nfp->count = 0;
				RB_INSERT(flow_tree, &flow_root, nfp);
			}

			count = fp->count; /* snapshot */
			nfp->count += count - fp->prev_count;
			fp->prev_count = count;
		}
	}

	if (RB_EMPTY(&flow_root)) {
		printf("flow tree is empty.\n");
		return;
	}

	RB_FOREACH(fp, flow_tree, &flow_root) {
		printf("count(flowid=0x%08x,flowtype=%u,flow_rssbucket=%u) = %lu\n",
		    fp->flowid, fp->flowtype, fp->flow_rssbucket, fp->count);
	}

	rss_config_free(rc);
}

static int
inet_aton6(const char *str, struct in6_addr *addr)
{
	struct addrinfo *res;
	int error;
	struct addrinfo hints;
	struct sockaddr_in6 s;

	memset(&hints, 0, sizeof(hints));

	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;
	hints.ai_protocol = 0;
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;

	error = getaddrinfo(str, NULL, &hints, &res);
	if (error != 0) {
		warn("%s: getaddrinfo", __func__);
		return (-1);
	}

	/* XXX ipv6 specific, tsk, use sockaddr_storage */
	memcpy(&s, res->ai_addr, res->ai_addrlen);
	*addr = s.sin6_addr;

	freeaddrinfo(res);
	return (0);
}

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

static void
printset(cpuset_t *mask)
{
	int once;
	int cpu;

	for (once = 0, cpu = 0; cpu < CPU_SETSIZE; cpu++) {
		if (CPU_ISSET(cpu, mask)) {
			if (once == 0) {
				printf("%d", cpu);
				once = 1;
			} else
				printf(", %d", cpu);
		}
	}
	printf("\n");
}

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

	if (debug && rss_sock_set_recvrss(fd, af_family, 1) < 0) {
		return (-1);
	}

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
thr_parse_sockaddr(const struct sockaddr *addr)
{
	const struct sockaddr_in *sa4;
	const struct sockaddr_in6 *sa6;
	char ipstr[INET6_ADDRSTRLEN];
	int port;

	switch (addr->sa_family) {
	case AF_INET:
		sa4 = (const struct sockaddr_in *) addr;
		inet_ntop(AF_INET, &sa4->sin_addr, ipstr, sizeof(ipstr));
		port = ntohs(sa4->sin_port);
		break;
	case AF_INET6:
		sa6 = (const struct sockaddr_in6 *) addr;
		inet_ntop(AF_INET6, &sa6->sin6_addr, ipstr, sizeof(ipstr));
		port = ntohs(sa6->sin6_port);
		break;
	}

	printf("  from: %s %d\n", ipstr, port);
}

static void
thr_parse_msghdr(struct msghdr *m, int af_family, void *arg)
{
	struct udp_srv_thread *th = arg;
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
		switch (af_family) {
		case AF_INET:
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
			break;
		case AF_INET6:
			if (c->cmsg_level != IPPROTO_IPV6)
				continue;
			switch (c->cmsg_type) {
				case IPV6_FLOWID:
					flowid = *(uint32_t *) CMSG_DATA(c);
					break;
				case IPV6_FLOWTYPE:
					flowtype = *(uint32_t *) CMSG_DATA(c);
					break;
				case IPV6_RSSBUCKETID:
					flow_rssbucket = *(uint32_t *) CMSG_DATA(c);
					break;
			}
			break;
		}
	}

	if (debug >= 2) {
		struct flow *nfp, *fp;

		nfp = malloc(sizeof(*nfp));
		if (nfp == NULL) {
			warn("%s: malloc", __func__);
			return;
		}

		nfp->flowid = flowid;
		nfp->flowtype = flowtype;
		nfp->flow_rssbucket = flow_rssbucket;

		fp = RB_FIND(flow_tree, &th->flow_root, nfp);
		if (fp == NULL) {
			nfp->count = 1;
			nfp->prev_count = 0;
			RB_INSERT(flow_tree, &th->flow_root, nfp);
		} else {
			fp->count++;
			free(nfp);
		}
		return;
	}

	printf("  flowid=0x%08x; flowtype=%d; bucket=%d\n", flowid, flowtype, flow_rssbucket);
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
thr_udp_ev_read(int fd, short what, void *arg, int af_family)
{
	struct udp_srv_thread *th = arg;
	/* XXX should be thread-local, and a larger buffer, and likely a queue .. */
	char buf[2048];
	ssize_t ret;
	int i = 0;
	struct sockaddr_storage sin;
	socklen_t sin_len;

	/* for the msghdr contents */
	struct msghdr m;
	char msgbuf[2048];

	struct iovec iov[1];

	/* Loop read UDP frames until EWOULDBLOCK or 1024 frames */
	while (i < 10240) {

		iov[0].iov_base = buf;
		iov[0].iov_len = sizeof(buf);

		m.msg_name = &sin;
		m.msg_namelen = sizeof(sin);
		m.msg_iov = iov;
		m.msg_iovlen = 1;
		m.msg_flags = 0;
		if (debug) {
			m.msg_control = &msgbuf;
			m.msg_controllen = sizeof(msgbuf);
		} else {
			m.msg_control = NULL;
			m.msg_controllen = 0;
		}

		ret = recvmsg(fd, &m, MSG_DONTWAIT);
		if (ret <= 0) {
			if (errno != EWOULDBLOCK)
				warn("%s: recv", __func__);
			break;
		}

		sin_len = m.msg_namelen;

		if (debug) {
			if (debug == 1) {
				printf("  recv: len=%d, controllen=%d\n",
				    (int) ret,
				    (int) m.msg_controllen);
				thr_parse_sockaddr((struct sockaddr *) &sin);
			}
			thr_parse_msghdr(&m, af_family, arg);
		}
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
thr_udp_ev_read4(int fd, short what, void *arg)
{
	thr_udp_ev_read(fd, what, arg, AF_INET);
}

static void
thr_udp_ev_read6(int fd, short what, void *arg)
{
	thr_udp_ev_read(fd, what, arg, AF_INET6);
}

static void *
thr_udp_srv_init(void *arg)
{
	struct udp_srv_thread *th = arg;
	int opt;
	socklen_t optlen;
	sigset_t sigs;
	int retval;
	char buf[128];
	struct timeval tv;

	/* Disable SIGINFO */
	if (sigemptyset(&sigs) == -1 || sigaddset(&sigs, SIGINFO) == -1
	    || pthread_sigmask(SIG_BLOCK, &sigs, NULL) != 0)
		warn("failed to ignore SIGINFO");

	/* thread pin for RSS */
	if (pthread_setaffinity_np(th->thr, sizeof(cpuset_t), &th->cs) != 0)
		warn("pthread_setaffinity_np (id %d)", th->tid);

	printf("[%d] th=%p\n", th->tid, th);
	snprintf(buf, 128, "(bucket %d)", th->rss_bucket);
	(void) pthread_set_name_np(th->thr, buf);

	th->b = event_base_new();
	th->s4 = -1;
	th->s6 = -1;

	/* IPv4 socket */
	if (th->v4_listen_port != -1) {
		th->s4 = thr_rss_listen_udp_sock_create_ipv4(th->rss_bucket,
		    th->v4_listen_addr, th->v4_listen_port);
		if (th->s4 < 0) {
			fprintf(stderr, "%s: ipv4 listen socket creation failed!\n", __func__);
		}
	}

	/* IPv6 socket */
	if (th->v6_listen_port != -1) {
		th->s6 = thr_rss_listen_sock_create_ipv6(th->rss_bucket,
		    th->v6_listen_addr, th->v6_listen_port);
		if (th->s6 < 0) {
			fprintf(stderr, "%s: ipv6 listen socket creation failed!\n", __func__);
		}
	}

	th->ev_timer = evtimer_new(th->b, thr_ev_timer, th);
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	evtimer_add(th->ev_timer, &tv);

	/* Create read and write readiness events */
	if (th->v4_listen_port != -1) {
		th->ev_read = event_new(th->b, th->s4, EV_READ | EV_PERSIST,
		    thr_udp_ev_read4, th);
		event_add(th->ev_read, NULL);
	}

	if (th->v6_listen_port != -1) {
		th->ev_read6 = event_new(th->b, th->s6, EV_READ | EV_PERSIST,
		    thr_udp_ev_read6, th);
		event_add(th->ev_read6, NULL);
	}

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
	if (th->ev_read6)
		event_free(th->ev_read6);
	printf("%s [%d]: done\n", __func__, th->tid);
	return (NULL);
}

static void
usage(const char *progname)
{
	fprintf(stderr,
	    "    [-r <0|1>] [-s <v4 listen address] [-S <v6 listen address]\n");
	fprintf(stderr,
	    "    [-p <v4 listen port>] [-P [v6 listen port] [-d[d]]\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	int i;
	struct udp_srv_thread *th;
	struct rss_config *rc;
	struct sigaction sa;
	struct in_addr lcl_addr;
	struct in6_addr lcl6_addr;
	int v4_port, v6_port;
	int do_response;
	int ch;

	lcl_addr.s_addr = INADDR_ANY;
	lcl6_addr = in6addr_any;
	v4_port = -1;
	v6_port = -1;

	while ((ch = getopt(argc, argv, "dhr:s:S:p:P:")) != -1) {
		switch (ch) {
		case 'd':
			debug += 1;
			break;
		case 'r':
			do_response = atoi(optarg);
			break;
		case 's':
			(void) inet_aton(optarg, &lcl_addr);
			break;
		case 'S':
			(void) inet_aton6(optarg, &lcl6_addr);
			break;
		case 'p':
			v4_port = atoi(optarg);
			break;
		case 'P':
			v6_port = atoi(optarg);
			break;
		case 'h':
		default:
			usage(argv[0]);
		}
	}

	if (v4_port == -1 && v6_port == -1) {
		fprintf(stderr,
		    "Error: at least one of v4,v6 port must be configured!\n");
		usage(argv[0]);
	}

	rc = rss_config_get();
	if (rc == NULL) {
		fprintf(stderr, "Couldn't fetch rss configuration\n");
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

	/* Allocate enough threads - one per bucket */
	th = calloc(rc->rss_nbuckets, sizeof(*th));
	if (th == NULL)
		err(127, "calloc");

	threads = th;

	for (i = 0; i < rc->rss_nbuckets; i++) {
		th[i].tid = i;
		th[i].rss_bucket = i;
		(void) rss_get_bucket_cpuset(rc,
		    RSS_BUCKET_TYPE_KERNEL_ALL,
		    i,
		    &th[i].cs);
		th[i].v4_listen_addr = lcl_addr;
		th[i].v4_listen_port = v4_port;
		th[i].v6_listen_addr = lcl6_addr;
		th[i].v6_listen_port = v6_port;
		th[i].do_response = do_response;
		RB_INIT(&th[i].flow_root);
		printf("starting: tid=%d, rss_bucket=%d, cpuset=",
		    th[i].tid,
		    th[i].rss_bucket);
		printset(&th[i].cs);
		(void) pthread_create(&th[i].thr, NULL, thr_udp_srv_init, &th[i]);
	}

	if (debug >= 2) {
		RB_INIT(&flow_root);
		signal(SIGINFO, flow_dump);
	}

	/* Wait */
	for (i = 0; i < rc->rss_nbuckets; i++) {
		(void) pthread_join(th[i].thr, NULL);
	}

	/* Finished! */
	rss_config_free(rc);

	exit(0);
}
