#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <event2/event.h>
#include <event2/thread.h>
#include <event2/util.h>

#include <err.h>

struct clt {
	int fd;
	struct {
		char *buf;
		int size;
	} rb, wb;
	const char *lcl_host, *rem_host;
	struct sockaddr_in lcl_sin;
	struct in_addr lcl_addr;
	struct sockaddr_in rem_sin;
	struct in_addr rem_addr;
	int cnt, cur_cnt;
	int port;
	int pkt_size;
	struct event *ev_read, *ev_write;
};

void
write_pkt(int fd, short what, void *arg)
{
	struct clt *c = arg;
	int i;
	int len;
	int r;

	for (i = 0; i < 128; i++) {
		len = c->pkt_size;

		r = sendto(c->fd, c->wb.buf, len, 0,
		    (struct sockaddr *) &c->rem_sin, sizeof(c->rem_sin));
		if (r < 0) {
			if (errno == EWOULDBLOCK || errno == ENOBUFS) {
				/* XXX should pause */
				break;
			}
			warn("%s: sendto", __func__);
		}
		c->cur_cnt ++;
		if (c->cur_cnt >= c->cnt)
			exit(1);
	}
}

void
read_pkt(int fd, short what, void *arg)
{
	struct clt *c = arg;
	int cnt;
	int r;
	int i;

	for (i = 0; i < 128; i++) {
		r = recv(c->fd, c->rb.buf, c->rb.size, MSG_DONTWAIT);
		if (r <= 0)
			break;
	}
}

int
main(int argc, const char *argv[])
{
	int r;
	int i = 0;
	struct clt *c;
	struct event_base *b;
	int opt;

	b = event_base_new();
	if (b == NULL)
		exit(128);

	c = calloc(1, sizeof(*c));
	if (c == NULL)
		err(1, "calloc");
	c->rb.buf = malloc(16384);
	c->rb.size = 16384;
	c->wb.buf = malloc(16384);
	c->wb.size = 16384;

	/* XXX validate args */
	c->lcl_host = strdup(argv[1]);
	c->rem_host = strdup(argv[2]);
	c->port = atoi(argv[3]);
	c->pkt_size = atoi(argv[4]);
	c->cnt = atoi(argv[5]);

	/* Socket setup */
	c->fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (c->fd < 0)
		err(1, "socket");

	/* Dont block */
	if ((opt = fcntl(c->fd, F_GETFL, 0)) < 0
	    || fcntl(c->fd, F_SETFL, opt | O_NONBLOCK) < 0) {
		err(1, "fcntl");
	}


	r = inet_aton(c->lcl_host, &c->lcl_addr);
	if (r < 0)
		err(1, "inet_aton");
	r = inet_aton(c->rem_host, &c->rem_addr);
	if (r < 0)
		err(1, "inet_aton");

	/* Local bind */
	bzero(&c->lcl_sin, sizeof(c->lcl_sin));
	c->lcl_sin.sin_family = AF_INET;
	c->lcl_sin.sin_port = 0;
	c->lcl_sin.sin_addr = c->lcl_addr;

	r = bind(c->fd, (struct sockaddr *) &c->lcl_sin, sizeof(c->lcl_sin));
	if (r < 0)
		err(1, "bind");

	/* Remote bind */
	bzero(&c->rem_sin, sizeof(c->rem_sin));
	c->rem_sin.sin_family = AF_INET;
	c->rem_sin.sin_port = htons(c->port);
	c->rem_sin.sin_addr = c->rem_addr;

	/* XXX randomize buf contents */
	for (r = 0; r < c->wb.size; r++) {
		c->wb.buf[r] = r;
	}

	c->ev_read = event_new(b, c->fd, EV_READ | EV_PERSIST, read_pkt, c);
	c->ev_write = event_new(b, c->fd, EV_WRITE | EV_PERSIST, write_pkt, c);
	event_add(c->ev_read, NULL);
	event_add(c->ev_write, NULL);

	(void) event_base_dispatch(b);

	exit(0);
}
