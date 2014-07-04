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
	int s;
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

static void *
thr_http_init(void *arg)
{
	struct http_srv_thread *th = arg;
	int opt;
	socklen_t optlen;
	cpuset_t cp;
	int retval;
	struct sockaddr_in sa;

	/* thread pin for RSS */
        CPU_ZERO(&cp);
        CPU_SET(th->cpuid, &cp);

        if (pthread_setaffinity_np(th->thr, sizeof(cpuset_t), &cp) != 0)
                warn("pthread_setaffinity_np (id %d)", th->tid);

	printf("[%d] th=%p\n", th->tid, th);

	th->b = event_base_new();
	/* XXX error */
	th->h = evhttp_new(th->b);
	/* XXX error */

	/* Hand-craft the socket bits */
	th->s = socket(PF_INET, SOCK_STREAM, 0);
	/* XXX error */

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

#if 1
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
#endif

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

        /* Bind */
        bzero(&sa, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons(8080);
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

	/* Dont block */
	if ((opt = fcntl(th->s, F_GETFL, 0)) < 0
	    || fcntl(th->s, F_SETFL, opt | O_NONBLOCK) < 0) {
		warn("%s: fcntl(O_NONBLOCK)\n", __func__);
		return (NULL);
	}

	/* Hand it to libevent */
	(void) evhttp_accept_socket(th->h, th->s);

	/* Default dispatch */
	(void) evhttp_set_gencb(th->h, thr_http_gen_cb, th);

	/* Dispatch loop */
	for (;;) {
		int ret;
		ret = event_base_dispatch(th->b);
		printf("%s [%d]: event_base_dispatch() returned %d\n", __func__, th->tid, ret);
	}
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
