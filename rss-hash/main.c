#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <err.h>

#define	RSS_KEYSIZE 40


#if 0
static uint8_t  rss_key[RSS_KEYSIZE] = {
        0x43, 0xa3, 0x8f, 0xb0, 0x41, 0x67, 0x25, 0x3d,
        0x25, 0x5b, 0x0e, 0xc2, 0x6d, 0x5a, 0x56, 0xda,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
#else
static uint8_t  rss_key[RSS_KEYSIZE] = {
	0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2,
	0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
	0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4,
	0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
	0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa
};
#endif

uint32_t
toeplitz_hash(u_int keylen, const uint8_t *key, u_int datalen,
    const uint8_t *data)
{
        uint32_t hash = 0, v;
        u_int i, b;

        /* XXXRW: Perhaps an assertion about key length vs. data length? */

        v = (key[0]<<24) + (key[1]<<16) + (key[2] <<8) + key[3];
        for (i = 0; i < datalen; i++) { 
                for (b = 0; b < 8; b++) {
                        if (data[i] & (1<<(7-b)))
                                hash ^= v;
                        v <<= 1;
                        if ((i + 4) < RSS_KEYSIZE &&
                            (key[i+4] & (1<<(7-b))))
                                v |= 1;
                }
        }
        return (hash);
}

/*
 * Hash an IPv4 4-tuple.
 */
uint32_t
rss_hash_ip4_4tuple(struct in_addr src, u_short srcport, struct in_addr dst,
    u_short dstport)
{
        uint8_t data[sizeof(src) + sizeof(dst) + sizeof(srcport) +
            sizeof(dstport)];
        u_int datalen;

        datalen = 0;
        bcopy(&src, &data[datalen], sizeof(src));
        datalen += sizeof(src);
        bcopy(&dst, &data[datalen], sizeof(dst));
        datalen += sizeof(dst);
        bcopy(&srcport, &data[datalen], sizeof(srcport));
        datalen += sizeof(srcport);
        bcopy(&dstport, &data[datalen], sizeof(dstport));
        datalen += sizeof(dstport);
	return (toeplitz_hash(sizeof(rss_key), rss_key, datalen, data));
}

/*
 * Hash an IPv6 4-tuple.
 */
uint32_t
rss_hash_ip6_4tuple(struct in6_addr src, u_short srcport,
    struct in6_addr dst, u_short dstport)
{
        uint8_t data[sizeof(src) + sizeof(dst) + sizeof(srcport) +
            sizeof(dstport)];
        u_int datalen;

        datalen = 0;
        bcopy(&src, &data[datalen], sizeof(src));
        datalen += sizeof(src);
        bcopy(&dst, &data[datalen], sizeof(dst));
        datalen += sizeof(dst);
        bcopy(&srcport, &data[datalen], sizeof(srcport));
        datalen += sizeof(srcport);
        bcopy(&dstport, &data[datalen], sizeof(dstport));
        datalen += sizeof(dstport);
        return (toeplitz_hash(sizeof(rss_key), rss_key, datalen, data));
}

int
main(int argc, char *argv[])
{
	struct in_addr src, dst;
	struct in6_addr src6, dst6;
	int af_family;
	u_short srcport, dstport;
	struct addrinfo *ai, a;
	int r;

	/* Lookup */
	bzero(&a, sizeof(a));
	a.ai_flags = AI_NUMERICHOST;
	a.ai_family = AF_UNSPEC;

	r = getaddrinfo(argv[1], NULL, &a, &ai);
	if (r < 0) {
		err(1, "%s: getaddrinfo(src)", argv[0]);
	}

	if (ai == NULL) {
		fprintf(stderr, "%s: src (%s) couldn't be decoded!\n", argv[0], argv[1]);
		exit(1);
	}

	af_family = -1;
	if (ai->ai_family == AF_INET) {
		af_family = AF_INET;
		printf("src=ipv4\n");
		src = ((struct sockaddr_in *) ai->ai_addr)->sin_addr;
	} else if (ai->ai_family == AF_INET6) {
		af_family = AF_INET6;
		printf("src=ipv6\n");
		src6 = ((struct sockaddr_in6 *) ai->ai_addr)->sin6_addr;
	} else {
		fprintf(stderr, "%s: src (%s) isn't ipv4 or ipv6!\n", argv[0], argv[1]);
	}

	srcport = htons(atoi(argv[2]));

	r = getaddrinfo(argv[3], NULL, &a, &ai);
	if (r < 0) {
		err(1, "%s: getaddrinfo(dst)", argv[0]);
	}

	if (ai == NULL) {
		fprintf(stderr, "%s: dst (%s) couldn't be decoded!\n", argv[0], argv[3]);
		exit(1);
	}

	/* XXX should check that this matches src type */
	if (ai->ai_family == AF_INET) {
		dst = ((struct sockaddr_in *) ai->ai_addr)->sin_addr;
	} else if (ai->ai_family == AF_INET6) {
		af_family = AF_INET6;
		dst6 = ((struct sockaddr_in6 *) ai->ai_addr)->sin6_addr;
	} else {
		fprintf(stderr, "%s: dst (%s) isn't ipv4 or ipv6!\n", argv[0], argv[3]);
	}

	dstport = htons(atoi(argv[4]));

	if (af_family == AF_INET) {
		printf("(v4) hash: 0x%08x\n",
		    rss_hash_ip4_4tuple(src, srcport, dst, dstport));
	} else if (af_family == AF_INET6) {
		printf("(v6) hash: 0x%08x\n",
		    rss_hash_ip6_4tuple(src6, srcport, dst6, dstport));
	}
#if 0
	/* IPv4 */
	(void) inet_aton(argv[1], &src);
	srcport = htons(atoi(argv[2]));
	(void) inet_aton(argv[3], &dst);

	printf("hash: 0x%08x\n",
	    rss_hash_ip4_4tuple(src, srcport, dst, dstport));
#endif

	exit (0);
}
