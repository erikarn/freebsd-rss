PROG=rss-udp-srv

SRCS=udp_srv.c
LDADD=-lpthread

# libevent
CFLAGS+=-I/home/adrian/local/include
LDFLAGS+=-L/home/adrian/local/lib/ -rpath /home/adrian/local/lib
LDADD+= -levent -levent_pthreads

# librss
CFLAGS+= -I${.CURDIR}/../librss/
LDFLAGS+= -L${.OBJDIR}/../librss/
LDADD+=-lrss

NO_MAN=1

.include <bsd.prog.mk>
