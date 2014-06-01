PROG=rss-http

SRCS=http.c rss.c

CFLAGS+=-I/usr/local/include
LDFLAGS+=-L/usr/local/lib/event2
LDADD=-lpthread -levent

NO_MAN=1

.include <bsd.prog.mk>
