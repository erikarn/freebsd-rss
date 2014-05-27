#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define	RSS_KEYSIZE 40


static uint8_t  rss_key[RSS_KEYSIZE] = {
        0x43, 0xa3, 0x8f, 0xb0, 0x41, 0x67, 0x25, 0x3d,
        0x25, 0x5b, 0x0e, 0xc2, 0x6d, 0x5a, 0x56, 0xda,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

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

int
main(int argc, char *argv[])
{
	struct in_addr src, dst;
	u_short srcport, dstport;

	(void) inet_aton(argv[1], &src);
	srcport = htons(atoi(argv[2]));
	(void) inet_aton(argv[3], &dst);
	dstport = htons(atoi(argv[4]));

	printf("hash: 0x%08x\n",
	    rss_hash_ip4_4tuple(src, srcport, dst, dstport));

	exit (0);
}
