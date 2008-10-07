#include "config.h"

#ifndef _WEBALIZER_H
#define _WEBALIZER_H

#define PCENT(val,max) ((val)?((double)val/(double)max)*100.0 : 0.0)
#define IDX_2C(c1,c2)       (((c1-'a'+1)<<5)+(c2-'a'+1) )
#define IDX_3C(c1,c2,c3)    (((c1-'a'+1)<<10)+((c2-'a'+1)<<5)+(c3-'a'+1) )
#define IDX_4C(c1,c2,c3,c4) (((c1-'a'+1)<<15)+((c2-'a'+1)<<10)+((c3-'a'+1)<<5)+(c4-'a'+1) )

#ifndef MAX
#define MAX(a,b) ((a) > (b) ? (a) : (b))
#endif

#define MAXHASH  2048                  /* Size of our hash tables          */
#define BUFSIZE  4096                  /* Max buffer size for log record   */
#define MAXHOST  128                   /* Max hostname buffer size         */
#define MAXURL   1024                  /* Max HTTP request/URL field size  */
#define MAXURLH  128                   /* Max URL field size in htab       */
#define MAXREF   1024                  /* Max referrer field size          */
#define MAXREFH  128                   /* Max referrer field size in htab  */
#define MAXAGENT 64                    /* Max user agent field size        */
#define MAXCTRY  48                    /* Max country name size            */
#define MAXSRCH  256                   /* Max size of search string buffer */
#define MAXSRCHH 64                    /* Max size of search str in htab   */
#define MAXIDENT 64                    /* Max size of ident string (user)  */

#define SLOP_VAL 3600                  /* out of sequence slop (seconds)   */

/* Log types */
#define LOG_CLF   0                        /* CLF/combined log type        */
#define LOG_FTP   1                        /* wu-ftpd xferlog type         */
#define LOG_SQUID 2                        /* squid proxy log              */

/* Response code defines as per draft ietf HTTP/1.1 rev 6 */
#define RC_CONTINUE           100
#define RC_SWITCHPROTO        101
#define RC_OK                 200
#define RC_CREATED            201
#define RC_ACCEPTED           202
#define RC_NONAUTHINFO        203
#define RC_NOCONTENT          204
#define RC_RESETCONTENT       205
#define RC_PARTIALCONTENT     206
#define RC_MULTIPLECHOICES    300
#define RC_MOVEDPERM          301
#define RC_MOVEDTEMP          302
#define RC_SEEOTHER           303
#define RC_NOMOD              304
#define RC_USEPROXY           305
#define RC_MOVEDTEMPORARILY   307
#define RC_BAD                400
#define RC_UNAUTH             401
#define RC_PAYMENTREQ         402
#define RC_FORBIDDEN          403
#define RC_NOTFOUND           404
#define RC_METHODNOTALLOWED   405
#define RC_NOTACCEPTABLE      406
#define RC_PROXYAUTHREQ       407
#define RC_TIMEOUT            408
#define RC_CONFLICT           409
#define RC_GONE               410
#define RC_LENGTHREQ          411
#define RC_PREFAILED          412
#define RC_REQENTTOOLARGE     413
#define RC_REQURITOOLARGE     414
#define RC_UNSUPMEDIATYPE     415
#define RC_RNGNOTSATISFIABLE  416
#define RC_EXPECTATIONFAILED  417
#define RC_SERVERERR          500
#define RC_NOTIMPLEMENTED     501
#define RC_BADGATEWAY         502
#define RC_UNAVAIL            503
#define RC_GATEWAYTIMEOUT     504
#define RC_BADHTTPVER         505

/* Index defines for RC codes */
#define IDX_UNDEFINED          0
#define IDX_CONTINUE           1
#define IDX_SWITCHPROTO        2
#define IDX_OK                 3
#define IDX_CREATED            4 
#define IDX_ACCEPTED           5 
#define IDX_NONAUTHINFO        6 
#define IDX_NOCONTENT          7  
#define IDX_RESETCONTENT       8 
#define IDX_PARTIALCONTENT     9 
#define IDX_MULTIPLECHOICES    10 
#define IDX_MOVEDPERM          11 
#define IDX_MOVEDTEMP          12 
#define IDX_SEEOTHER           13 
#define IDX_NOMOD              14 
#define IDX_USEPROXY           15 
#define IDX_MOVEDTEMPORARILY   16
#define IDX_BAD                17 
#define IDX_UNAUTH             18 
#define IDX_PAYMENTREQ         19 
#define IDX_FORBIDDEN          20 
#define IDX_NOTFOUND           21 
#define IDX_METHODNOTALLOWED   22 
#define IDX_NOTACCEPTABLE      23 
#define IDX_PROXYAUTHREQ       24 
#define IDX_TIMEOUT            25 
#define IDX_CONFLICT           26 
#define IDX_GONE               27 
#define IDX_LENGTHREQ          28 
#define IDX_PREFAILED          29 
#define IDX_REQENTTOOLARGE     30 
#define IDX_REQURITOOLARGE     31 
#define IDX_UNSUPMEDIATYPE     32
#define IDX_RNGNOTSATISFIABLE  33
#define IDX_EXPECTATIONFAILED  34 
#define IDX_SERVERERR          35 
#define IDX_NOTIMPLEMENTED     36 
#define IDX_BADGATEWAY         37 
#define IDX_UNAVAIL            38 
#define IDX_GATEWAYTIMEOUT     39 
#define IDX_BADHTTPVER         40 
#define TOTAL_RC               41

#ifdef USE_DNS
#include <netinet/in.h>       /* needed for in_addr structure definition   */
#ifndef INADDR_NONE
#define INADDR_NONE 0xFFFFFFFF
#endif  /* INADDR_NONE */
#endif

/* Response code structure */
struct response_code {   int       resp_code;
                         char     *desc;         /* response code struct  */
                         u_long    count; };

/* Country code structure */
struct	country_code { u_long idx;
                         char *desc;
                       u_long count;
                       u_long files;
                       double  xfer; };

typedef struct country_code *CLISTPTR;

/* log record structure */
struct  log_struct  {  char   hostname[MAXHOST];   /* hostname             */
                       char   datetime[29];        /* raw timestamp        */
                       char   url[MAXURL];         /* raw request field    */
                       int    resp_code;           /* response code        */
                       u_long xfer_size;           /* xfer size in bytes   */
#ifdef USE_DNS
                       struct in_addr addr;        /* IP address structure */
#endif  /* USE_DNS */
                       char   refer[MAXREF];       /* referrer             */
                       char   agent[MAXAGENT];     /* user agent (browser) */
                       char   srchstr[MAXSRCH];    /* search string        */
                       char   ident[MAXIDENT]; };  /* ident string (user)  */

extern struct log_struct log_rec;

extern char    *version     ;                 /* program version          */
extern char    *editlvl     ;                 /* edit level               */
extern char    *moddate     ;                 /* modification date        */
extern char    *copyright   ;

extern int     verbose      ;                 /* 2=verbose,1=err, 0=none  */ 
extern int     debug_mode   ;                 /* debug mode flag          */
extern int     time_me      ;                 /* timing display flag      */
extern int     local_time   ;                 /* 1=localtime 0=GMT (UTC)  */
extern int     ignore_hist  ;                 /* history flag (1=skip)    */
extern int     hourly_graph ;                 /* hourly graph display     */
extern int     hourly_stats ;                 /* hourly stats table       */
extern int     daily_graph  ;                 /* daily graph display      */
extern int     daily_stats  ;                 /* daily stats table        */
extern int     ctry_graph   ;                 /* country graph display    */
extern int     shade_groups ;                 /* Group shading 0=no 1=yes */
extern int     hlite_groups ;                 /* Group hlite 0=no 1=yes   */
extern int     mangle_agent ;                 /* mangle user agents       */
extern int     incremental  ;                 /* incremental mode 1=yes   */
extern int     use_https    ;                 /* use 'https://' on URL's  */
extern int     visit_timeout;                 /* visit timeout (30 min)   */
extern int     graph_legend ;                 /* graph legend (1=yes)     */
extern int     graph_lines  ;                 /* graph lines (0=none)     */
extern int     fold_seq_err ;                 /* fold seq err (0=no)      */
extern int     log_type     ;                 /* (0=clf, 1=ftp, 2=squid)  */
extern int     group_domains;                 /* Group domains 0=none     */
extern int     hide_sites   ;                 /* Hide ind. sites (0=no)   */
extern char    *hname       ;                 /* hostname for reports     */
extern char    *state_fname ;                 /* run state file name      */
extern char    *hist_fname  ;                 /* name of history file     */
extern char    *html_ext    ;                 /* HTML file prefix         */
extern char    *dump_ext    ;                 /* Dump file prefix         */
extern char    *conf_fname  ;                 /* name of config file      */
extern char    *log_fname   ;                 /* log file pointer         */
extern char    *out_dir     ;                 /* output directory         */
extern char    *blank_str   ;                 /* blank string             */
extern char    *dns_cache   ;                 /* DNS cache file name      */
extern int     dns_children ;                 /* # of DNS children        */
extern char    *stylesheet  ;                 /* XSL stylesheet to use    */

extern int     ntop_sites   ;                 /* top n sites to display   */
extern int     ntop_sitesK  ;                 /* top n sites (by kbytes)  */
extern int     ntop_urls    ;                 /* top n url's to display   */
extern int     ntop_urlsK   ;                 /* top n url's (by kbytes)  */
extern int     ntop_entry   ;                 /* top n entry url's        */
extern int     ntop_exit    ;                 /* top n exit url's         */
extern int     ntop_refs    ;                 /* top n referrers ""       */
extern int     ntop_agents  ;                 /* top n user agents ""     */
extern int     ntop_ctrys   ;                 /* top n countries   ""     */
extern int     ntop_search  ;                 /* top n search strings     */
extern int     ntop_users   ;                 /* top n users to display   */

extern int     all_sites    ;                 /* List All sites (0=no)    */
extern int     all_urls     ;                 /* List All URL's (0=no)    */
extern int     all_refs     ;                 /* List All Referrers       */
extern int     all_agents   ;                 /* List All User Agents     */
extern int     all_search   ;                 /* List All Search Strings  */
extern int     all_users    ;                 /* List All Usernames       */

extern int     dump_sites   ;                 /* Dump tab delimited sites */
extern int     dump_urls    ;                 /* URL's                    */
extern int     dump_refs    ;                 /* Referrers                */
extern int     dump_agents  ;                 /* User Agents              */
extern int     dump_users   ;                 /* Usernames                */
extern int     dump_search  ;                 /* Search strings           */
extern int     dump_header  ;                 /* Dump header as first rec */
extern char    *dump_path   ;                 /* Path for dump files      */

extern u_long  cur_tstamp;                    /* Current timestamp        */
extern u_long  epoch;                         /* used for timestamp adj.  */
extern int     check_dup;                     /* check for dups flag      */

extern int     cur_year,cur_month,            /* year/month/day/hour      */
               cur_day, cur_hour,             /* tracking variables       */
               cur_min, cur_sec;

extern double  t_xfer;                        /* monthly total xfer value */
extern u_long  t_hit, t_file, t_site,         /* monthly total vars       */
               t_url, t_ref,  t_agent,
               t_page,t_visit,t_user;

extern double  tm_xfer[31];                   /* daily transfer totals    */

extern u_long  tm_hit[31], tm_file[31],       /* daily total arrays       */
               tm_site[31],tm_page[31],
               tm_visit[31];

extern u_long  dt_site;                       /* daily 'sites' total      */

extern u_long  ht_hit,mh_hit;                 /* hourly hits totals       */

extern u_long  th_hit[24], th_file[24],       /* hourly total arrays      */
               th_page[24];

extern double  th_xfer[24];

extern int     f_day,l_day;                   /* first/last day vars      */
extern int     gz_log;                        /* flag for zipped log      */

extern CLISTPTR *top_ctrys;                   /* Top countries table      */

/* define our externally visable functions */

extern char   *cur_time();
extern u_long ctry_idx(char *);
extern void   init_counters();
extern int    ispage(char *);
extern u_long jdate(int,int,int);

#endif  /* _WEBALIZER_H */
