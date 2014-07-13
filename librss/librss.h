#ifndef	__LIBRSS_H__
#define	__LIBRSS_H__

extern	int rss_sock_set_bindmulti(int fd, int af_family, int val);
extern	int rss_sock_set_rss_bucket(int fd, int af_family, int rss_bucket);

/*
 * Enable or disable receiving RSS/flowid information on
 * received UDP frames.
 */
extern	int rss_sock_set_recvrss(int fd, int af_family, int val);

extern	int rss_getsysctlint(const char *s);
extern	int rss_getbucketmap(int *bucket_map, int nbuckets);

#endif /* __LIBRSS_H__ */
