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

#include <netinet/in.h>

#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include <event2/http.h>
#include <event2/thread.h>

#include "rss.h"

struct http_srv_thread {
	pthread_t thr;
	int tid;
	int rss_bucket;
	int cpuid;
	int s4, s6;
	struct event_base *b;
	struct evhttp *h;
};

static void
thr_http_free_cb(const void *data, size_t datalen, void *extra)
{

	free((void *)data);
}

static void
thr_http_gen_cb(struct evhttp_request *req, void *cbdata)
{
	struct http_srv_thread *th = cbdata;
	struct evbuffer *evb;
	char *buf;

	buf = malloc(1024);

	/* Just return 200 OK with some data for now */
	evb = evbuffer_new();
	evbuffer_add_printf(evb, "OK\r\n");
	evbuffer_add_reference(evb, buf, 1024, thr_http_free_cb, NULL);
	evhttp_send_reply(req, HTTP_OK, "OK", evb);
	/*
	 * evhttp_send_reply() -> evhttp_send() will copy the evbuffer data
	 * into its own private data buffer.
	 */
	evbuffer_free(evb);
}

static int
thr_sock_set_bindmulti(int fd, int af_family, int val)
{
	int opt;
	socklen_t optlen;
	int retval;

	/* Set bindmulti */
	opt = val;
	optlen = sizeof(opt);
	retval = setsockopt(fd,
	    af_family == AF_INET ? IPPROTO_IP : IPPROTO_IPV6,
	    af_family == AF_INET ? IP_BINDMULTI : IPV6_BINDMULTI,
	    &opt,
	    optlen);
	if (retval < 0) {
		warn("%s: setsockopt(IP_BINDMULTI)", __func__);
		return (-1);
	}
	return (0);
}

static int
thr_sock_set_rss_bucket(int fd, int af_family, int rss_bucket)
{
	int opt;
	socklen_t optlen;
	int retval;

	/* Set RSS bucket */
	opt = rss_bucket;
	optlen = sizeof(opt);
	retval = setsockopt(fd,
	    af_family == AF_INET ? IPPROTO_IP : IPPROTO_IPV6,
	    af_family == AF_INET ? IP_RSS_LISTEN_BUCKET : IPV6_RSS_LISTEN_BUCKET,
	    &opt,
	    optlen);
	if (retval < 0) {
		warn("%s: setsockopt(IP_RSS_LISTEN_BUCKET)", __func__);
		return (-1);
	}
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

/*
 * Setup the RSS state for a listen socket.
 *
 * Call after socket creation, before bind() and listen().
 */
static int
thr_rss_listen_sock_setup(int fd, int af_family, int rss_bucket)
{

	if (thr_sock_set_bindmulti(fd, af_family, 1) < 0) {
		return (-1);
	}

	if (thr_sock_set_rss_bucket(fd, af_family, rss_bucket) < 0) {
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
thr_rss_listen_sock_create_ipv4(int rss_bucket)
{
	int fd;
	struct sockaddr_in sa4;
	int opt;
	int retval;

	/* IPv4 */
	fd = socket(PF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		warn("%s: socket()", __func__);
		goto error;
	}

	if (thr_rss_listen_sock_setup(fd, AF_INET, rss_bucket) < 0) {
		goto error;
	}

	/* Bind */
	bzero(&sa4, sizeof(sa4));
	sa4.sin_family = AF_INET;
	sa4.sin_port = htons(8080);
	sa4.sin_addr.s_addr = INADDR_ANY;

	retval = bind(fd, (struct sockaddr *) &sa4, sizeof(sa4));
	if (retval < 0) {
		warn("%s: bind()", __func__);
		goto error;
	}

	/* Listen */
	retval = listen(fd, -1);
	if (retval < 0) {
		warn("%s: listen()", __func__);
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
thr_rss_listen_sock_create_ipv6(int rss_bucket)
{
	int fd;
	struct sockaddr_in6 sa6;
	int opt;
	int retval;

	/* IPv6 */
	fd = socket(PF_INET6, SOCK_STREAM, 0);
	if (fd < 0) {
		warn("%s: socket()", __func__);
		goto error;
	}

	if (thr_rss_listen_sock_setup(fd, AF_INET6, rss_bucket) < 0) {
		goto error;
	}

	/* Bind */
	bzero(&sa6, sizeof(sa6));
	sa6.sin6_family = AF_INET6;
	sa6.sin6_port = htons(8080);
	sa6.sin6_addr = in6addr_any;

	retval = bind(fd, (struct sockaddr *) &sa6, sizeof(sa6));
	if (retval < 0) {
		warn("%s: bind()", __func__);
		goto error;
	}

	/* Listen */
	retval = listen(fd, -1);
	if (retval < 0) {
		warn("%s: listen()", __func__);
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

static void *
thr_http_init(void *arg)
{
	struct http_srv_thread *th = arg;
	int opt;
	socklen_t optlen;
	cpuset_t cp;
	int retval;
	struct sockaddr_in6 sa6;
	char buf[128];

	/* thread pin for RSS */
	CPU_ZERO(&cp);
	CPU_SET(th->cpuid, &cp);

	if (pthread_setaffinity_np(th->thr, sizeof(cpuset_t), &cp) != 0)
		warn("pthread_setaffinity_np (id %d)", th->tid);

	printf("[%d] th=%p\n", th->tid, th);
	snprintf(buf, 128, "(bucket %d)", th->rss_bucket);
	(void) pthread_set_name_np(th->thr, buf);

	th->b = event_base_new();
	th->h = evhttp_new(th->b);
	th->s4 = -1;
	th->s6 = -1;

	/* IPv4 socket */
	th->s4 = thr_rss_listen_sock_create_ipv4(th->rss_bucket);
	if (th->s4 < 0) {
		fprintf(stderr, "%s: ipv4 listen socket creation failed!\n", __func__);
	}

	/* IPv6 socket */
	th->s6 = thr_rss_listen_sock_create_ipv6(th->rss_bucket);
	if (th->s6 < 0) {
		fprintf(stderr, "%s: ipv6 listen socket creation failed!\n", __func__);
	}

	/* Hand it to libevent */
	if (th->s4 != -1)
		(void) evhttp_accept_socket(th->h, th->s4);
	if (th->s6 != -1)
		(void) evhttp_accept_socket(th->h, th->s6);

	/* Default dispatch */
	(void) evhttp_set_gencb(th->h, thr_http_gen_cb, th);

	/* Dispatch loop */
	for (;;) {
		int ret;
		ret = event_base_dispatch(th->b);
		printf("%s [%d]: event_base_dispatch() returned %d\n", __func__, th->tid, ret);
	}

finish:
	/* XXX wrap up http state? sockets? */
	if (th->s4 != -1)
		close(th->s4);
	if (th->s6 != -1)
		close(th->s6);
	printf("%s [%d]: done\n", __func__, th->tid);
	return (NULL);
}

int
main(int argc, char *argv[])
{
	int i;
	struct http_srv_thread *th;
	int ncpu;
	int nbuckets;
	int base_cpu;
	int *bucket_map;
	struct sigaction sa;

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
		printf("starting: tid=%d, rss_bucket=%d, cpuid=%d\n",
		    th[i].tid,
		    th[i].rss_bucket,
		    th[i].cpuid);
		(void) pthread_create(&th[i].thr, NULL, thr_http_init, &th[i]);
	}

	/* Wait */
	for (i = 0; i < nbuckets; i++) {
		(void) pthread_join(th[i].thr, NULL);
	}

	exit(0);
}
