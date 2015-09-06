#ifndef	__LIBRSS_H__
#define	__LIBRSS_H__

struct rss_config {
	int rss_ncpus;
	int rss_nbuckets;
	int rss_basecpu;
	int *rss_bucket_map;
};

/*
 * Enable/disable whether to allow for multiple bind()s to the
 * given PCB entry.
 *
 * This must be done before bind().
 */
extern	int rss_sock_set_bindmulti(int fd, int af_family, int val);

/*
 * Set the RSS bucket for the given file descriptor.
 *
 * This must be done before bind().
 */
extern	int rss_sock_set_rss_bucket(int fd, int af_family, int rss_bucket);

/*
 * Enable or disable receiving RSS/flowid information on
 * received UDP frames.
 */
extern	int rss_sock_set_recvrss(int fd, int af_family, int val);

#if 0
/*
 * Generic "retrive the int value for the given sysctl"
 * worker function.
 */
extern	int rss_getsysctlint(const char *s);

/*
 * Retrieve the mapping between RSS bucket and
 * CPU ID.
 */
extern	int rss_getbucketmap(int *bucket_map, int nbuckets);
#endif

/*
 * Fetch RSS configuration information.
 */
extern	struct rss_config * rss_config_get(void);

/*
 * Free an RSS configuration structure.
 */
extern	void rss_config_free(struct rss_config *rc);

#endif /* __LIBRSS_H__ */
