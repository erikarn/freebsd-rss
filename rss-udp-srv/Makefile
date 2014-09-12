PROG=rss-udp-srv

SRCS=udp_srv.c
LDADD=-lpthread

# libevent
CFLAGS+=-I/usr/local/include
LDFLAGS+=-L/usr/local/lib/
LDADD+= -levent -levent_pthreads

# librss
CFLAGS+= -I${.CURDIR}/../librss/
LDFLAGS+= -L${.OBJDIR}/../librss/
LDADD+=-lrss

NO_MAN=1

.include <bsd.prog.mk>
