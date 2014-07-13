#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <err.h>


int
main(int argc, const char *argv[])
{
	const char *host;
	int port;
	struct sockaddr_in sin;
	int r;
	char buf[2048];
	int fd;
	struct in_addr addr;

	/* XXX validate args */
	host = strdup(argv[1]);
	port = atoi(argv[2]);

	fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		err(1, "socket");

	r = inet_aton(host, &addr);
	if (r != 0)
		err(1, "inet_aton");

	/* Local bind */
	bzero(&sin, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = 0;
	sin.sin_addr.s_addr = INADDR_ANY;

	r = bind(fd, (struct sockaddr *) &sin, sizeof(sin));
	if (r < 0)
		err(1, "bind");

	/* Remote bind */
	bzero(&sin, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr = addr;

	/* XXX randomize buf contents */
	for (r = 0; r < sizeof(buf); r++) {
		buf[r] = r;
	}

	/* Loop sending */
	while (1) {
		r = sendto(fd, buf, 2048, 0, (struct sockaddr *) &sin, sizeof(sin));
		if (r < 0)
			warn("%s: sendto", __func__);
			break;
	}

	exit(0);
}
