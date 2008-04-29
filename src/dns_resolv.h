#ifndef _DNS_RESOLV_H
#define _DNS_RESOLV_H

#ifdef USE_DNS    /* skip whole file if not using DNS stuff...             */

#ifdef HAVE_ERRNO_H
#include <errno.h>
#else
extern int  errno;
#endif  /* HAVE_ERRNO_H */

struct dnsRecord { time_t    timeStamp;       /* Timestamp of resolv data  */
                   int       numeric;         /* 0: Name, 1: IP-address    */
                   char      hostName[1]; };  /* Hostname (var length)     */

struct dns_child             /* Defines the communication with a DNS child */
{
  int inpipe[2];             /* Pipe Child  -> Father */
  int outpipe[2];            /* Pipe Father -> Child */
  int pid;                   /* PID of Child */
  int flags;                 /* see below */
  struct dnode *cur;         /* Currently processed node */
};

extern void resolve_dns(struct log_struct *);
extern DB   *dns_db;
extern int  dns_fd;
extern int  dns_resolver(void *);
extern int  open_cache();
extern int  close_cache();

#define DNS_CHILD_READY   0x1         /* Our child flags                    */
#define DNS_CHILD_RUNNING 0x2

#define MAXCHILD          100         /* Maximum number of DNS children     */
#define DNS_CACHE_TTL     86400*3     /* TTL of an Entry in the DNS cache   */

#endif  /* USE_DNS */
#endif  /* _DNS_RESOLV_H */
