#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <strings.h>
#include <err.h>
#include <fcntl.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/cpuset.h>
#include <sys/sysctl.h>

#include <netinet/in.h>

#include "librss.h"

int
rss_sock_set_bindmulti(int fd, int af_family, int val)
{
	int opt;
	socklen_t optlen;
	int retval;

	/* Set bindmulti */
	opt = val;
	optlen = sizeof(opt);
	retval = setsockopt(fd,
	    af_family == AF_INET ? IPPROTO_IP : IPPROTO_IPV6,
	    af_family == AF_INET ? IP_BINDMULTI : IPV6_BINDMULTI,
	    &opt,
	    optlen);
	if (retval < 0) {
		warn("%s: setsockopt(IP_BINDMULTI)", __func__);
		return (-1);
	}
	return (0);
}

int
rss_sock_set_rss_bucket(int fd, int af_family, int rss_bucket)
{
	int opt;
	socklen_t optlen;
	int retval;

	/* Set RSS bucket */
	opt = rss_bucket;
	optlen = sizeof(opt);
	retval = setsockopt(fd,
	    af_family == AF_INET ? IPPROTO_IP : IPPROTO_IPV6,
	    af_family == AF_INET ? IP_RSS_LISTEN_BUCKET : IPV6_RSS_LISTEN_BUCKET,
	    &opt,
	    optlen);
	if (retval < 0) {
		warn("%s: setsockopt(IP_RSS_LISTEN_BUCKET)", __func__);
		return (-1);
	}
	return (0);
}

int
rss_sock_set_recvrss(int fd, int af_family, int val)
{
	int opt, retval;
	socklen_t optlen;

	/* Enable/disable flowid */
	opt = val;
	optlen = sizeof(opt);
	retval = setsockopt(fd,
	    IPPROTO_IP,
	    IP_RECVFLOWID,
	    &opt,
	    optlen);
	if (retval < 0) {
		warn("%s: setsockopt(IP_RECVFLOWID)", __func__);
		return (-1);
	}

	/* Enable/disable RSS bucket reception */
	opt = val;
	optlen = sizeof(opt);
	retval = setsockopt(fd,
	    IPPROTO_IP,
	    IP_RECVRSSBUCKETID,
	    &opt,
	    optlen);
	if (retval < 0) {
		warn("%s: setsockopt(IP_RECVRSSBUCKETID)", __func__);
		return (-1);
	}

	return (0);
}

int
rss_getsysctlint(const char *s)
{
	int val, retval;
	size_t rlen;

	rlen = sizeof(int);
	retval = sysctlbyname(s, &val, &rlen, NULL, 0);
	if (retval < 0) {
		warn("sysctlbyname (%s)", s);
		return (-1);
	}

	return (val);
}

int
rss_getbucketmap(int *bucket_map, int nbuckets)
{
	/* XXX I'm lazy; so static string it is */
	char bstr[2048];
	int retval, i;
	size_t rlen;
	char *s, *ss;
	int r, b, c;

	/* Paranoia */
	memset(bstr, '\0', sizeof(bstr));

	rlen = sizeof(bstr) - 1;
	retval = sysctlbyname("net.inet.rss.bucket_mapping", bstr, &rlen, NULL, 0);
	if (retval < 0) {
		warn("sysctlbyname (net.inet.rss.bucket_mapping)");
		return (-1);
	}

	ss = bstr;
	while ((s =strsep(&ss, " ")) != NULL) {
		r = sscanf(s, "%d:%d", &b, &c);
		if (r != 2) {
			fprintf(stderr, "%s: string (%s) not parsable\n",
			    __func__,
			    s);
			return (-1);
		}
		if (b > nbuckets) {
			fprintf(stderr, "%s: bucket %d > nbuckets %d\n",
			    __func__,
			    b,
			    nbuckets);
			return (-1);
		}
		/* XXX no maxcpu check */
		bucket_map[b] = c;
	}
	return (0);
}
