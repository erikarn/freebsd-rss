#ifndef	__LIBRSS_H__
#define	__LIBRSS_H__

struct rss_config {
	int rss_ncpus;
	int rss_nbuckets;
	int rss_basecpu;
	int *rss_bucket_map;
};

typedef enum {
	RSS_BUCKET_TYPE_NONE = 0,
	RSS_BUCKET_TYPE_KERNEL_ALL = 1,
	RSS_BUCKET_TYPE_KERNEL_TX = 2,
	RSS_BUCKET_TYPE_KERNEL_RX = 3,
	RSS_BUCKET_TYPE_MAX = 3,
} rss_bucket_type_t;

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

/*
 * Fetch RSS configuration information.
 */
extern	struct rss_config * rss_config_get(void);

/*
 * Free an RSS configuration structure.
 */
extern	void rss_config_free(struct rss_config *rc);

/*
 * Fetch the cpuset configuration for the given RSS bucket and
 * type.
 */
extern	int rss_get_bucket_cpuset(struct rss_config *rc,
    rss_bucket_type_t btype, int bucket, cpuset_t *cs);

#endif /* __LIBRSS_H__ */
