/*
    webalizer - a web server log analysis program

    Copyright (C) 1997-2001  Bradford L. Barrett (brad@mrunix.net)

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version, and provided that the above
    copyright and permission notice is included with all distributed
    copies of this or derived software.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA

    This software uses the gd graphics library, which is copyright by
    Quest Protein Database Center, Cold Spring Harbor Labs.  Please
    see the documentation supplied with the library for additional
    information and license terms, or visit www.boutell.com/gd/ for the
    most recent version of the library and supporting documentation.
*/

/*********************************************/
/* STANDARD INCLUDES                         */
/*********************************************/

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>                           /* normal stuff             */
#include <ctype.h>
#include <sys/utsname.h>
#include <sys/times.h>
#include <zlib.h>

/* ensure getopt */
#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

/* ensure sys/types */
#ifndef _SYS_TYPES_H
#include <sys/types.h>
#endif

/* some systems need this */
#ifdef HAVE_MATH_H
#include <math.h>
#endif

/* SunOS 4.x Fix */
#ifndef CLK_TCK
#define CLK_TCK _SC_CLK_TCK
#endif

#ifdef USE_DNS
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef HAVE_DB_185_H
#include <db_185.h>
#else
#include <db.h>
#endif  /* HAVE_DB_185_H */
#endif  /* USE_DNS */

#include "webalizer.h"                         /* main header              */
#include "xmloutput.h"
#include "parser.h"
#include "preserve.h"
#include "hashtab.h"
#include "linklist.h"
#include "webalizer_lang.h"                    /* lang. support            */
#ifdef USE_DNS
#include "dns_resolv.h"
#endif

/* internal function prototypes */

void    clear_month();                              /* clear monthly stuff */
char    *unescape(char *);                          /* unescape URL's      */
char    from_hex(char);                             /* convert hex to dec  */
void    print_opts(char *);                         /* print options       */
void    print_version();                            /* duhh...             */
int     isurlchar(unsigned char);                   /* valid URL char fnc. */
void    get_config(char *);                         /* Read a config file  */
static  char *save_opt(char *);                     /* save conf option    */
void    srch_string(char *);                        /* srch str analysis   */
char	*get_domain(char *);                        /* return domain name  */
char    *our_gzgets(gzFile, char *, int);           /* our gzgets          */

/*********************************************/
/* GLOBAL VARIABLES                          */
/*********************************************/

char    *version     = "0.01";                /* program version          */
char    *editlvl     = "11";                  /* edit level               */
char    *moddate     = "07-Oct-2008";         /* modification date        */
char    *copyright   = "Copyright 1997-2001 by Bradford L. Barrett";

int     verbose      = 2;                     /* 2=verbose,1=err, 0=none  */ 
int     debug_mode   = 0;                     /* debug mode flag          */
int     xml_mode     = 0;                     /* debug mode flag          */
int     time_me      = 0;                     /* timing display flag      */
int     local_time   = 1;                     /* 1=localtime 0=GMT (UTC)  */
int     ignore_hist  = 0;                     /* history flag (1=skip)    */
int     hourly_graph = 1;                     /* hourly graph display     */
int     hourly_stats = 1;                     /* hourly stats table       */
int     daily_graph  = 1;                     /* daily graph display      */
int     daily_stats  = 1;                     /* daily stats table        */
int     ctry_graph   = 1;                     /* country graph display    */
int     shade_groups = 1;                     /* Group shading 0=no 1=yes */
int     hlite_groups = 1;                     /* Group hlite 0=no 1=yes   */
int     mangle_agent = 0;                     /* mangle user agents       */
int     incremental  = 0;                     /* incremental mode 1=yes   */
int     use_https    = 0;                     /* use 'https://' on URL's  */
int     visit_timeout= 1800;                  /* visit timeout (seconds)  */
int     graph_legend = 1;                     /* graph legend (1=yes)     */
int     graph_lines  = 2;                     /* graph lines (0=none)     */
int     fold_seq_err = 0;                     /* fold seq err (0=no)      */
int     log_type     = LOG_CLF;               /* (0=clf, 1=ftp, 2=squid)  */
int     group_domains= 0;                     /* Group domains 0=none     */
int     hide_sites   = 0;                     /* Hide ind. sites (0=no)   */
char    *hname       = NULL;                  /* hostname for reports     */
char    *state_fname = "webalizer.current";   /* run state file name      */
char    *hist_fname  = "webalizer.hist";      /* name of history file     */
char    *html_ext    = "html";                /* HTML file prefix         */
char    *dump_ext    = "tab";                 /* Dump file prefix         */
char    *conf_fname  = NULL;                  /* name of config file      */
char    *log_fname   = NULL;                  /* log file pointer         */
char    *out_dir     = NULL;                  /* output directory         */
char    *blank_str   = "";                    /* blank string             */
char    *dns_cache   = NULL;                  /* DNS cache file name      */
int     dns_children = 0;                     /* DNS children (0=don't do)*/
char	*stylesheet	 = NULL;				  /* XSL URI string (in xml)  */

int     ntop_sites   = 30;                    /* top n sites to display   */
int     ntop_sitesK  = 10;                    /* top n sites (by kbytes)  */
int     ntop_urls    = 30;                    /* top n url's to display   */
int     ntop_urlsK   = 10;                    /* top n url's (by kbytes)  */
int     ntop_entry   = 10;                    /* top n entry url's        */
int     ntop_exit    = 10;                    /* top n exit url's         */
int     ntop_refs    = 30;                    /* top n referrers ""       */
int     ntop_agents  = 15;                    /* top n user agents ""     */
int     ntop_ctrys   = 30;                    /* top n countries   ""     */
int     ntop_search  = 20;                    /* top n search strings     */
int     ntop_users   = 20;                    /* top n users to display   */

int     all_sites    = 0;                     /* List All sites (0=no)    */
int     all_urls     = 0;                     /* List All URL's (0=no)    */
int     all_refs     = 0;                     /* List All Referrers       */
int     all_agents   = 0;                     /* List All User Agents     */
int     all_search   = 0;                     /* List All Search Strings  */
int     all_users    = 0;                     /* List All Usernames       */

int     dump_sites   = 0;                     /* Dump tab delimited sites */
int     dump_urls    = 0;                     /* URL's                    */
int     dump_refs    = 0;                     /* Referrers                */
int     dump_agents  = 0;                     /* User Agents              */
int     dump_users   = 0;                     /* Usernames                */
int     dump_search  = 0;                     /* Search strings           */
int     dump_header  = 0;                     /* Dump header as first rec */
char    *dump_path   = NULL;                  /* Path for dump files      */

int     cur_year=0, cur_month=0,              /* year/month/day/hour      */
        cur_day=0, cur_hour=0,                /* tracking variables       */
        cur_min=0, cur_sec=0;

u_long  cur_tstamp=0;                         /* Timestamp...             */
u_long  rec_tstamp=0;  
u_long  req_tstamp=0;
u_long  epoch;                                /* used for timestamp adj.  */

int     check_dup=0;                          /* check for dup flag       */
int     gz_log=0;                             /* gziped log? (0=no)       */

double  t_xfer=0.0;                           /* monthly total xfer value */
u_long  t_hit=0,t_file=0,t_site=0,            /* monthly total vars       */
        t_url=0,t_ref=0,t_agent=0,
        t_page=0, t_visit=0, t_user=0;

double  tm_xfer[31];                          /* daily transfer totals    */

u_long  tm_hit[31], tm_file[31],              /* daily total arrays       */
        tm_site[31], tm_page[31],
        tm_visit[31];

u_long  dt_site;                              /* daily 'sites' total      */

u_long  ht_hit=0, mh_hit=0;                   /* hourly hits totals       */

u_long  th_hit[24], th_file[24],              /* hourly total arrays      */
        th_page[24];

double  th_xfer[24];

int     f_day,l_day;                          /* first/last day vars      */

struct  utsname system_info;                  /* system info structure    */

u_long  ul_bogus =0;                          /* Dummy counter for groups */

struct  log_struct log_rec;                   /* expanded log storage     */

time_t  now;                                  /* used by cur_time funct   */
struct  tm *tp;                               /* to generate timestamp    */
char    timestamp[32];                        /* for the reports          */

gzFile  gzlog_fp;                             /* gzip logfile pointer     */
FILE    *log_fp;                              /* regular logfile pointer  */

char    buffer[BUFSIZE];                      /* log file record buffer   */
char    tmp_buf[BUFSIZE];                     /* used to temp save above  */

CLISTPTR *top_ctrys    = NULL;                /* Top countries table      */

#define GZ_BUFSIZE 16384                      /* our_getfs buffer size    */
char    f_buf[GZ_BUFSIZE];                    /* our_getfs buffer         */
char    *f_cp=f_buf+GZ_BUFSIZE;               /* pointer into the buffer  */
int     f_end;                                /* count to end of buffer   */ 

/*********************************************/
/* MAIN - start here                         */
/*********************************************/

int main(int argc, char *argv[])
{
   int      i;                           /* generic counter             */
   char     *cp1, *cp2, *cp3, *str;      /* generic char pointers       */
   NLISTPTR lptr;                        /* generic list pointer        */

   extern char *optarg;                  /* used for command line       */
   extern int optind;                    /* parsing routine 'getopt'    */
   extern int opterr;

   time_t start_time, end_time;          /* program timers              */
   float  temp_time;                     /* temporary time storage      */
   struct tms     mytms;                 /* bogus tms structure         */

   int    rec_year,rec_month=1,rec_day,rec_hour,rec_min,rec_sec;

   int    good_rec    =0;                /* 1 if we had a good record   */
   u_long total_rec   =0;                /* Total Records Processed     */
   u_long total_ignore=0;                /* Total Records Ignored       */
   u_long total_bad   =0;                /* Total Bad Records           */

   int    max_ctry;                      /* max countries defined       */

   /* month names used for parsing logfile (shouldn't be lang specific) */
   char *log_month[12]={ "jan", "feb", "mar",
                         "apr", "may", "jun",
                         "jul", "aug", "sep",
                         "oct", "nov", "dec"};

   /* initalize epoch */
   epoch=jdate(1,1,1970);                /* used for timestamp adj.     */

   /* add default index. alias */
   add_nlist("index.",&index_alias);

   snprintf(tmp_buf, sizeof(tmp_buf),"%s/webalizer.conf",ETCDIR);
   /* check for default config file */
   if (!access("webalizer.conf",F_OK))
      get_config("webalizer.conf");
   else if (!access(tmp_buf,F_OK))
      get_config(tmp_buf);

   /* get command line options */
   opterr = 0;     /* disable parser errors */
   while ((i=getopt(argc,argv,"a:A:b:c:C:dD:e:E:fF:g:GhHiI:l:Lm:M:n:N:o:pP:qQr:R:s:S:t:Tu:U:vVx:XYz:Z:"))!=EOF)
   {
      switch (i)
      {
	case 'b': xml_mode=1;     	     break;  /* Danny's mod */
        case 'a': add_nlist(optarg,&hidden_agents); break; /* Hide agents   */
        case 'A': ntop_agents=atoi(optarg);  break;  /* Top agents          */
        case 'c': get_config(optarg);        break;  /* Config file         */
        case 'C': ntop_ctrys=atoi(optarg);   break;  /* Top countries       */
        case 'd': debug_mode=1;              break;  /* Debug               */
	case 'D': dns_cache=optarg;          break;  /* DNS Cache filename  */
        case 'e': ntop_entry=atoi(optarg);   break;  /* Top entry pages     */
        case 'E': ntop_exit=atoi(optarg);    break;  /* Top exit pages      */
        case 'f': fold_seq_err=1;            break;  /* Fold sequence errs  */
        case 'F': log_type=(optarg[0]=='f')?
                   LOG_FTP:(optarg[0]=='s')?
                   LOG_SQUID:LOG_CLF;        break;  /* define log type     */
	case 'g': group_domains=atoi(optarg); break; /* GroupDomains (0=no) */
        case 'G': hourly_graph=0;            break;  /* no hourly graph     */
        case 'h': print_opts(argv[0]);       break;  /* help                */
        case 'H': hourly_stats=0;            break;  /* no hourly stats     */
        case 'i': ignore_hist=1;             break;  /* Ignore history      */
        case 'I': add_nlist(optarg,&index_alias); break; /* Index alias     */
        case 'l': graph_lines=atoi(optarg);  break;  /* Graph Lines         */
        case 'L': graph_legend=0;            break;  /* Graph Legends       */
        case 'm': visit_timeout=atoi(optarg); break; /* Visit Timeout       */
        case 'M': mangle_agent=atoi(optarg); break;  /* mangle user agents  */
        case 'n': hname=optarg;              break;  /* Hostname            */
        case 'N': dns_children=atoi(optarg); break;  /* # of DNS children   */
        case 'o': out_dir=optarg;            break;  /* Output directory    */
        case 'p': incremental=1;             break;  /* Incremental run     */
        case 'P': add_nlist(optarg,&page_type); break; /* page view types   */
        case 'q': verbose=1;                 break;  /* Quiet (verbose=1)   */
        case 'Q': verbose=0;                 break;  /* Really Quiet        */
        case 'r': add_nlist(optarg,&hidden_refs);   break; /* Hide referrer */
        case 'R': ntop_refs=atoi(optarg);    break;  /* Top referrers       */
        case 's': add_nlist(optarg,&hidden_sites);  break; /* Hide site     */
        case 'S': ntop_sites=atoi(optarg);   break;  /* Top sites           */
        case 't': msg_title=optarg;          break;  /* Report title        */
        case 'T': time_me=1;                 break;  /* TimeMe              */
        case 'u': add_nlist(optarg,&hidden_urls);   break; /* hide URL      */
        case 'U': ntop_urls=atoi(optarg);    break;  /* Top urls            */
        case 'v':
        case 'V': print_version();           break;  /* Version             */
        case 'x': html_ext=optarg;           break;  /* HTML file extension */
        case 'X': hide_sites=1;              break;  /* Hide ind. sites     */
        case 'Y': ctry_graph=0;              break;  /* Supress ctry graph  */
        case 'z': stylesheet=optarg;		 break;	 /* xsl stylesheet      */
      }
   }

   if (argc - optind != 0) log_fname = argv[optind];
   if ( log_fname && (log_fname[0]=='-')) log_fname=NULL; /* force STDIN?   */

   /* check for gzipped file - .gz */
   if (log_fname) if (!strcmp((log_fname+strlen(log_fname)-3),".gz")) gz_log=1;

   /* setup our internal variables */
   init_counters();                      /* initalize main counters         */

   if (page_type==NULL)                  /* check if page types present     */
   {
      if ((log_type == LOG_CLF) || (log_type == LOG_SQUID))
      {
         add_nlist("htm*"  ,&page_type); /* if no page types specified, we  */
         add_nlist("cgi"   ,&page_type); /* use the default ones here...    */
         if (!isinlist(page_type,html_ext)) add_nlist(html_ext,&page_type);
      }
      else add_nlist("txt" ,&page_type); /* FTP logs default to .txt        */
   }

   for (max_ctry=0;ctry[max_ctry].desc;max_ctry++);
   if (ntop_ctrys > max_ctry) ntop_ctrys = max_ctry;   /* force upper limit */
   if (graph_lines> 20)       graph_lines= 20;         /* keep graphs sane! */

   if (log_type == LOG_FTP)
   {
      /* disable stuff for ftp logs */
      ntop_entry=ntop_exit=0;
      ntop_search=0;
   }
   else
   {
      if (search_list==NULL)
      {
         /* If no search engines defined, define some :) */
         add_glist("yahoo.com      p="      ,&search_list);
         add_glist("altavista.com  q="      ,&search_list);
         add_glist("google.com     q="      ,&search_list);
         add_glist("eureka.com     q="      ,&search_list);
         add_glist("lycos.com      query="  ,&search_list);
         add_glist("hotbot.com     MT="     ,&search_list);
         add_glist("msn.com        MT="     ,&search_list);
         add_glist("infoseek.com   qt="     ,&search_list);
         add_glist("webcrawler searchText=" ,&search_list);
         add_glist("excite         search=" ,&search_list);
         add_glist("netscape.com   search=" ,&search_list);
         add_glist("mamma.com      query="  ,&search_list);
         add_glist("alltheweb.com  query="  ,&search_list);
         add_glist("northernlight.com qr="  ,&search_list);
      }
   }

   /* ensure entry/exits don't exceed urls */
   i=(ntop_urls>ntop_urlsK)?ntop_urls:ntop_urlsK;
   if (ntop_entry>i) ntop_entry=i;
   if (ntop_exit>i)  ntop_exit=i;

   for (i=0;i<MAXHASH;i++)
   {
      sm_htab[i]=sd_htab[i]=NULL;        /* initalize hash tables           */
      um_htab[i]=NULL;
      rm_htab[i]=NULL;
      am_htab[i]=NULL;
      sr_htab[i]=NULL;
   }

   /* Be polite and announce yourself... */
   if (verbose>1)
   {
      uname(&system_info);
      printf("Webalizer V%s-%s (%s %s) %s\n",
              version,editlvl,system_info.sysname,
              system_info.release,language);
   }

#ifndef USE_DNS
   if (strstr(argv[0],"webazolver")!=0)
   {
      printf("DNS support not present, aborting...\n");
      exit(1);
   }
#endif  /* USE_DNS */

   /* open log file */
   if (gz_log)
   {
      gzlog_fp = gzopen(log_fname,"rb");
      if (gzlog_fp==Z_NULL)
      {
         /* Error: Can't open log file ... */
         fprintf(stderr, "%s %s\n",msg_log_err,log_fname);
         exit(1);
      }
   }
   else
   {
      if (log_fname)
      {
         log_fp = fopen(log_fname,"r");
         if (log_fp==NULL)
         {
            /* Error: Can't open log file ... */
            fprintf(stderr, "%s %s\n",msg_log_err,log_fname);
            exit(1);
         }
      }
   }

   /* Using logfile ... */
   if (verbose>1)
   {
      printf("%s %s (",msg_log_use,log_fname?log_fname:"STDIN");
      if (gz_log) printf("gzip-");
      switch (log_type)
      {
         /* display log file type hint */
         case LOG_CLF:   printf("clf)\n");   break;
         case LOG_FTP:   printf("ftp)\n");   break;
         case LOG_SQUID: printf("squid)\n"); break;
      }
   }

   /* switch directories if needed */
   if (out_dir)
   {
      if (chdir(out_dir) != 0)
      {
         /* Error: Can't change directory to ... */
         fprintf(stderr, "%s %s\n",msg_dir_err,out_dir);
         exit(1);
      }
   }

#ifdef USE_DNS
   if (strstr(argv[0],"webazolver")!=0)
   {
      if (!dns_children) dns_children=5;  /* default dns children if needed */
      if (!dns_cache)
      {
         /* No cache file specified, aborting... */
         fprintf(stderr,"%s\n",msg_dns_nocf);     /* Must have a cache file */
         exit(1);
      }
   }

   if (dns_cache && dns_children)    /* run-time resolution */
   {
      if (dns_children > MAXCHILD) dns_children=MAXCHILD;
      /* DNS Lookup (#children): */
      if (verbose>1) printf("%s (%d): ",msg_dns_rslv,dns_children);
      fflush(stdout);
      (gz_log)?dns_resolver(gzlog_fp):dns_resolver(log_fp);
      (gz_log)?gzrewind(gzlog_fp):(log_fname)?rewind(log_fp):exit(0);
   }

   if (strstr(argv[0],"webazolver")!=0) exit(0);   /* webazolver exits here */

   if (dns_cache)
   {
      if (!open_cache()) { dns_cache=NULL; dns_db=NULL; }
      else
      {
         /* Using DNS cache file <filaneme> */
         if (verbose>1) printf("%s %s\n",msg_dns_usec,dns_cache);
      }
   }
#endif  /* USE_DNS */

   /* Creating output in ... */
   if (verbose>1)
      printf("%s %s\n",msg_dir_use,out_dir?out_dir:msg_cur_dir);

   /* prep hostname */
   if (!hname)
   {
      if (uname(&system_info)) hname="localhost";
      else hname=system_info.nodename;
   }

   /* Hostname for reports is ... */
   if (verbose>1) printf("%s '%s'\n",msg_hostname,hname);

   /* get past history */
   if (ignore_hist) {if (verbose>1) printf("%s\n",msg_ign_hist); }
   else get_history();

   if (incremental)                      /* incremental processing?         */
   {
      if ((i=restore_state()))           /* restore internal data structs   */
      {
         /* Error: Unable to restore run data (error num) */
         /* if (verbose) fprintf(stderr,"%s (%d)\n",msg_bad_data,i); */
         fprintf(stderr,"%s (%d)\n",msg_bad_data,i);
         exit(1);
      }
   }

   /* Allocate memory for our TOP countries array */
   if (ntop_ctrys  != 0)
   { if ( (top_ctrys=calloc(ntop_ctrys,sizeof(CLISTPTR))) == NULL)
    /* Can't get memory, Top Countries disabled! */
    {if (verbose) fprintf(stderr,"%s\n",msg_nomem_tc); ntop_ctrys=0;}}

   start_time = times(&mytms);

   /*********************************************/
   /* MAIN PROCESS LOOP - read through log file */
   /*********************************************/

   while ( (gz_log)?(our_gzgets(gzlog_fp,buffer,BUFSIZE) != Z_NULL):
           (fgets(buffer,BUFSIZE,log_fname?log_fp:stdin) != NULL))
   {
      total_rec++;
      if (strlen(buffer) == (BUFSIZE-1))
      {
         if (verbose)
         {
            fprintf(stderr,"%s",msg_big_rec);
            if (debug_mode) fprintf(stderr,":\n%s",buffer);
            else fprintf(stderr,"\n");
         }

         total_bad++;                     /* bump bad record counter      */

         /* get the rest of the record */
         while ( (gz_log)?(our_gzgets(gzlog_fp,buffer,BUFSIZE)!=Z_NULL):
                 (fgets(buffer,BUFSIZE,log_fname?log_fp:stdin)!=NULL))
         {
            if (strlen(buffer) < BUFSIZE-1)
            {
               if (debug_mode && verbose) fprintf(stderr,"%s\n",buffer);
               break;
            }
            if (debug_mode && verbose) fprintf(stderr,"%s",buffer);
         }
         continue;                        /* go get next record if any    */
      }

      /* got a record... */
      strcpy(tmp_buf, buffer);            /* save buffer in case of error */
      if (parse_record(buffer))           /* parse the record             */
      {
         /*********************************************/
         /* PASSED MINIMAL CHECKS, DO A LITTLE MORE   */
         /*********************************************/

         /* convert month name to lowercase */
         for (i=4;i<7;i++)
            log_rec.datetime[i]=tolower(log_rec.datetime[i]);

         /* get year/month/day/hour/min/sec values    */
         for (i=0;i<12;i++)
         {
            if (strncmp(log_month[i],&log_rec.datetime[4],3)==0)
               { rec_month = i+1; break; }
         }

         rec_year=atoi(&log_rec.datetime[8]);    /* get year number (int)   */
         rec_day =atoi(&log_rec.datetime[1]);    /* get day number          */
         rec_hour=atoi(&log_rec.datetime[13]);   /* get hour number         */
         rec_min =atoi(&log_rec.datetime[16]);   /* get minute number       */
         rec_sec =atoi(&log_rec.datetime[19]);   /* get second number       */

         /* Kludge for Netscape server time (0-24?) error                   */
         if (rec_hour>23) rec_hour=0;

         /* minimal sanity check on date */
         if ((i>=12)||(rec_min>59)||(rec_sec>59)||(rec_year<1990))
         {
            total_bad++;                /* if a bad date, bump counter      */
            if (verbose)
            {
               fprintf(stderr,"%s: %s [%lu]",
                 msg_bad_date,log_rec.datetime,total_rec);
               if (debug_mode) fprintf(stderr,":\n%s\n",tmp_buf);
               else fprintf(stderr,"\n");
            }
            continue;                   /* and ignore this record           */
         }

         /*********************************************/
         /* GOOD RECORD, CHECK INCREMENTAL/TIMESTAMPS */
         /*********************************************/

         /* Flag as a good one */
         good_rec = 1;

         /* get current records timestamp (seconds since epoch) */
         req_tstamp=cur_tstamp;
         rec_tstamp=((jdate(rec_day,rec_month,rec_year)-epoch)*86400)+
                     (rec_hour*3600)+(rec_min*60)+rec_sec;

         /* Do we need to check for duplicate records? (incremental mode)   */
         if (check_dup)
         {
            /* check if less than/equal to last record processed            */
            if ( rec_tstamp <= cur_tstamp )
            {
               /* if it is, assume we have already processed and ignore it  */
               total_ignore++;
               continue;
            }
            else
            {
               /* if it isn't.. disable any more checks this run            */
               check_dup=0;
               /* now check if it's a new month                             */
               if (cur_month != rec_month)
               {
                  clear_month();
                  cur_sec   = rec_sec;          /* set current counters     */
                  cur_min   = rec_min;
                  cur_hour  = rec_hour;
                  cur_day   = rec_day;
                  cur_month = rec_month;
                  cur_year  = rec_year;
                  cur_tstamp= rec_tstamp;
                  f_day=l_day=rec_day;          /* reset first and last day */
               }
            }
         }

         /* check for out of sequence records */
         if (rec_tstamp/3600 < cur_tstamp/3600)
         {
            if (!fold_seq_err && ((rec_tstamp+SLOP_VAL)/3600<cur_tstamp/3600) )
               { total_ignore++; continue; }
            else
            {
               rec_sec   = cur_sec;             /* if folding sequence      */
               rec_min   = cur_min;             /* errors, just make it     */
               rec_hour  = cur_hour;            /* look like the last       */
               rec_day   = cur_day;             /* good records timestamp   */
               rec_month = cur_month;
               rec_year  = cur_year;
               rec_tstamp= cur_tstamp;
            }
         }
         cur_tstamp=rec_tstamp;                 /* update current timestamp */

         /*********************************************/
         /* DO SOME PRE-PROCESS FORMATTING            */
         /*********************************************/

         /* fix URL field */
         cp1 = cp2 = log_rec.url;
         /* handle null '-' case here... */
         if (*++cp1 == '-') { *cp2++ = '-'; *cp2 = '\0'; }
         else
         {
            /* strip actual URL out of request */
            while  ( (*cp1 != ' ') && (*cp1 != '\0') ) cp1++;
            if (*cp1 != '\0')
            {
               /* scan to begin of actual URL field */
               while ((*cp1 == ' ') && (*cp1 != '\0')) cp1++;
               /* remove duplicate / if needed */
               if (( *cp1=='/') && (*(cp1+1)=='/')) cp1++;
               while ((*cp1 != ' ')&&(*cp1 != '"')&&(*cp1 != '\0'))
                  *cp2++ = *cp1++;
               *cp2 = '\0';
            }
         }

         /* un-escape URL */
         unescape(log_rec.url);

         /* check for service (ie: http://) and lowercase if found */
         if ( (cp2=strstr(log_rec.url,"://")) != NULL)
         {
            cp1=log_rec.url;
            while (cp1!=cp2)
            {
               if ( (*cp1>='A') && (*cp1<='Z')) *cp1 += 'a'-'A';
               cp1++;
            }
         }

         /* strip query portion of cgi scripts */
         cp1 = log_rec.url;
         while (*cp1 != '\0')
           if (!isurlchar(*cp1)) { *cp1 = '\0'; break; }
           else cp1++;
         if (log_rec.url[0]=='\0')
           { log_rec.url[0]='/'; log_rec.url[1]='\0'; }

         /* strip off index.html (or any aliases) */
         lptr=index_alias;
         while (lptr!=NULL)
         {
            if ((cp1=strstr(log_rec.url,lptr->string))!=NULL)
            {
               if ((cp1==log_rec.url)||(*(cp1-1)=='/'))
               {
                  *cp1='\0';
                  if (log_rec.url[0]=='\0')
                   { log_rec.url[0]='/'; log_rec.url[1]='\0'; }
                  break;
               }
            }
            lptr=lptr->next;
         }

         /* unescape referrer */
         unescape(log_rec.refer);

         /* fix referrer field */
         cp1 = log_rec.refer;
         cp3 = cp2 = cp1++;
         if ( (*cp2 != '\0') && (*cp2 == '"') )
         {
            while ( *cp1 != '\0' )
            {
               cp3=cp2;
               if ((*cp1<32&&*cp1>0) || *cp1==127 || *cp1=='<') *cp1=0;
               else *cp2++=*cp1++;
            }
            *cp3 = '\0';
         }

         /* strip query portion of cgi referrals */
         cp1 = log_rec.refer;
         if (*cp1 != '\0')
         {
            while (*cp1 != '\0')
            {
               if (!isurlchar(*cp1))
               {
                  /* Save query portion in log.rec.srchstr */
                  strncpy(log_rec.srchstr,cp1,MAXSRCH);
                  *cp1++='\0';
                  break;
               }
               else cp1++;
            }
            /* handle null referrer */
            if (log_rec.refer[0]=='\0')
              { log_rec.refer[0]='-'; log_rec.refer[1]='\0'; }
         }

         /* if HTTP request, lowercase http://sitename/ portion */
         cp1 = log_rec.refer;
         if ( (*cp1=='h') || (*cp1=='H'))
         {
            while ( (*cp1!='/') && (*cp1!='\0'))
            {
               if ( (*cp1>='A') && (*cp1<='Z')) *cp1 += 'a'-'A';
               cp1++;
            }
            /* now do hostname */
            if ( (*cp1=='/') && ( *(cp1+1)=='/')) {cp1++; cp1++;}
            while ( (*cp1!='/') && (*cp1!='\0'))
            {
               if ( (*cp1>='A') && (*cp1<='Z')) *cp1 += 'a'-'A';
               cp1++;
            }
         }

         /* Do we need to mangle? */
         if (mangle_agent)
         {
            str=cp2=log_rec.agent;
	    cp1=strstr(str,"ompatible"); /* check known fakers */
	    if (cp1!=NULL) {
		while (*cp1!=';'&&*cp1!='\0') cp1++;
		/* kludge for Mozilla/3.01 (compatible;) */
		if (*cp1++==';' && strcmp(cp1,")\"")) { /* success! */
		    while (*cp1 == ' ') cp1++; /* eat spaces */
		    while (*cp1!='.'&&*cp1!='\0'&&*cp1!=';') *cp2++=*cp1++;
		    if (mangle_agent<5)
		    {
			while (*cp1!='.'&&*cp1!=';'&&*cp1!='\0') *cp2++=*cp1++;
			if (*cp1!=';'&&*cp1!='\0') {
			    *cp2++=*cp1++;
			    *cp2++=*cp1++;
			}
		    }
		    if (mangle_agent<4)
			if (*cp1>='0'&&*cp1<='9') *cp2++=*cp1++;
		    if (mangle_agent<3)
			while (*cp1!=';'&&*cp1!='\0'&&*cp1!='(') *cp2++=*cp1++;
		    if (mangle_agent<2)
		    {
			/* Level 1 - try to get OS */
			cp1=strstr(str,")");
			if (cp1!=NULL)
			{
			    *cp2++=' ';
			    *cp2++='(';
			    while (*cp1!=';'&&*cp1!='('&&cp1!=str) cp1--;
			    if (cp1!=str&&*cp1!='\0') cp1++;
			    while (*cp1==' '&&*cp1!='\0') cp1++;
			    while (*cp1!=')'&&*cp1!='\0') *cp2++=*cp1++;
			    *cp2++=')';
			}
		    }
		    *cp2='\0';
		} else { /* nothing after "compatible", should we mangle? */
		    /* not for now */
		}
	    } else {
		cp1=strstr(str,"Opera");  /* Opera flavor         */
		if (cp1!=NULL)
		{
		    while (*cp1!='/'&&*cp1!=' '&&*cp1!='\0') *cp2++=*cp1++;
		    while (*cp1!='.'&&*cp1!='\0') *cp2++=*cp1++;
		    if (mangle_agent<5)
		    {
			while (*cp1!='.'&&*cp1!='\0') *cp2++=*cp1++;
			*cp2++=*cp1++;
			*cp2++=*cp1++;
		    }
		    if (mangle_agent<4)
			if (*cp1>='0'&&*cp1<='9') *cp2++=*cp1++;
		    if (mangle_agent<3)
			while (*cp1!=' '&&*cp1!='\0'&&*cp1!='(') 
			    *cp2++=*cp1++;
		    if (mangle_agent<2)
		    {
			cp1=strstr(str,"(");
			if (cp1!=NULL)
			{
			    cp1++;
			    *cp2++=' ';
			    *cp2++='(';
			    while (*cp1!=';'&&*cp1!=')'&&*cp1!='\0') 
				*cp2++=*cp1++;
			    *cp2++=')';
			}
		    }
		    *cp2='\0';
		} else { 
		    cp1=strstr(str,"Mozilla");  /* Netscape flavor      */
		    if (cp1!=NULL)
		    {
			while (*cp1!='/'&&*cp1!=' '&&*cp1!='\0') *cp2++=*cp1++;
			if (*cp1==' ') *cp1='/';
			while (*cp1!='.'&&*cp1!='\0') *cp2++=*cp1++;
			if (mangle_agent<5)
			{
			    while (*cp1!='.'&&*cp1!='\0') *cp2++=*cp1++;
			    *cp2++=*cp1++;
			    *cp2++=*cp1++;
			}
			if (mangle_agent<4)
			    if (*cp1>='0'&&*cp1<='9') *cp2++=*cp1++;
			if (mangle_agent<3)
			    while (*cp1!=' '&&*cp1!='\0'&&*cp1!='(') 
				*cp2++=*cp1++;
			if (mangle_agent<2)
			{
			    /* Level 1 - Try to get OS */
			    cp1=strstr(str,"(");
			    if (cp1!=NULL)
			    {
				cp1++;
				*cp2++=' ';
				*cp2++='(';
				while (*cp1!=';'&&*cp1!=')'&&*cp1!='\0') 
				    *cp2++=*cp1++;
				*cp2++=')';
			    }
			}
			*cp2='\0';
		    }
		}
	    }
	 }

         /* if necessary, shrink referrer to fit storage */
         if (strlen(log_rec.refer)>=MAXREFH)
         {
            if (verbose) fprintf(stderr,"%s [%lu]\n",
                msg_big_ref,total_rec);
            log_rec.refer[MAXREFH-1]='\0';
         }

         /* if necessary, shrink URL to fit storage */
         if (strlen(log_rec.url)>=MAXURLH)
         {
            if (verbose) fprintf(stderr,"%s [%lu]\n",
                msg_big_req,total_rec);
            log_rec.url[MAXURLH-1]='\0';
         }

         /* fix user agent field */
         cp1 = log_rec.agent;
         cp3 = cp2 = cp1++;
         if ( (*cp2 != '\0') && ((*cp2 == '"')||(*cp2 == '(')) )
         {
            while (*cp1 |= '\0') { cp3 = cp2; *cp2++ = *cp1++; }
            *cp3 = '\0';
         }
         cp1 = log_rec.agent;    /* CHANGE !!! */
         while (*cp1 != 0)       /* get rid of more common _bad_ chars ;)   */
         {
            if ( (*cp1 < 32) || (*cp1==127) || (*cp1=='<') || (*cp1=='>') )
               { *cp1='\0'; break; }
            else cp1++;
         }

         /* fix username if needed */
         if (log_rec.ident[0]==0)
          {  log_rec.ident[0]='-'; log_rec.ident[1]='\0'; }
         else
         {
            cp3=log_rec.ident;
            while (*cp3>=32 && *cp3!='"') cp3++;
            *cp3='\0';
         }
         /* unescape user name */
         unescape(log_rec.ident);

         /********************************************/
         /* PROCESS RECORD                           */
         /********************************************/

         /* first time through? */
         if (cur_month == 0)
         {
             /* if yes, init our date vars */
             cur_month=rec_month; cur_year=rec_year;
             cur_day=rec_day; cur_hour=rec_hour;
             cur_min=rec_min; cur_sec=rec_sec;
             f_day=rec_day;
         }

         /* adjust last day processed if different */
         if (rec_day > l_day) l_day = rec_day;
 
         /* update min/sec stuff */
         if (cur_sec != rec_sec) cur_sec = rec_sec;
         if (cur_min != rec_min) cur_min = rec_min;

         /* check for hour change  */
         if (cur_hour != rec_hour)
         {
            /* if yes, init hourly stuff */
            if (ht_hit > mh_hit) mh_hit = ht_hit;
            ht_hit = 0;
            cur_hour = rec_hour;
         }

         /* check for day change   */
         if (cur_day != rec_day)
         {
            /* if yes, init daily stuff */
            tm_site[cur_day-1]=dt_site; dt_site=0;
            tm_visit[cur_day-1]=tot_visit(sd_htab);
            del_hlist(sd_htab);
            cur_day = rec_day;
         }

         /* check for month change */
         if (cur_month != rec_month)
         {
            /* if yes, do monthly stuff */
            t_visit=tot_visit(sm_htab);
            month_update_exit(req_tstamp);    /* process exit pages      */
            //write_month_html();               /* generate HTML for month */
			write_month_xml();
            clear_month();
            cur_month = rec_month;            /* update our flags        */
            cur_year  = rec_year;
            f_day=l_day=rec_day;
         }

#ifdef USE_DNS
         /* Resolve IP address if needed */
         if (dns_db)
         {
            if (inet_addr(log_rec.hostname) != INADDR_NONE)
            resolve_dns(&log_rec);
         }
#endif

         /* lowercase hostname */
         cp1 = log_rec.hostname;
         while (*cp1 != '\0')
         {
            if ( (*cp1>='A') && (*cp1<='Z') ) *cp1 += 'a'-'A';
            if ( (isalnum((int)*cp1))||(*cp1=='.')||(*cp1=='-') ) cp1++;
            else *cp1='\0';
         }

         /* Catch blank hostnames here */
         if (log_rec.hostname[0]=='\0')
            strncpy(log_rec.hostname,"Unknown",8);

         /* Ignore/Include check */
         if ( (isinlist(include_sites,log_rec.hostname)==NULL) &&
              (isinlist(include_urls,log_rec.url)==NULL)       &&
              (isinlist(include_refs,log_rec.refer)==NULL)     &&
              (isinlist(include_agents,log_rec.agent)==NULL)   &&
              (isinlist(include_users,log_rec.ident)==NULL)    )
         {
            if (isinlist(ignored_sites,log_rec.hostname)!=NULL)
              { total_ignore++; continue; }
            if (isinlist(ignored_urls,log_rec.url)!=NULL)
              { total_ignore++; continue; }
            if (isinlist(ignored_agents,log_rec.agent)!=NULL)
              { total_ignore++; continue; }
            if (isinlist(ignored_refs,log_rec.refer)!=NULL)
              { total_ignore++; continue; }
            if (isinlist(ignored_users,log_rec.ident)!=NULL)
              { total_ignore++; continue; }
         }

         /* Bump response code totals */
         switch (log_rec.resp_code) {
          case RC_CONTINUE:         i=IDX_CONTINUE;         break;
          case RC_SWITCHPROTO:      i=IDX_SWITCHPROTO;      break;
          case RC_OK:               i=IDX_OK;               break;
          case RC_CREATED:          i=IDX_CREATED;          break;
          case RC_ACCEPTED:         i=IDX_ACCEPTED;         break;
          case RC_NONAUTHINFO:      i=IDX_NONAUTHINFO;      break;
          case RC_NOCONTENT:        i=IDX_NOCONTENT;        break;
          case RC_RESETCONTENT:     i=IDX_RESETCONTENT;     break;
          case RC_PARTIALCONTENT:   i=IDX_PARTIALCONTENT;   break;
          case RC_MULTIPLECHOICES:  i=IDX_MULTIPLECHOICES;  break;
          case RC_MOVEDPERM:        i=IDX_MOVEDPERM;        break;
          case RC_MOVEDTEMP:        i=IDX_MOVEDTEMP;        break;
          case RC_SEEOTHER:         i=IDX_SEEOTHER;         break;
          case RC_NOMOD:            i=IDX_NOMOD;            break;
          case RC_USEPROXY:         i=IDX_USEPROXY;         break;
 	  case RC_MOVEDTEMPORARILY: i=IDX_MOVEDTEMPORARILY; break;
          case RC_BAD:              i=IDX_BAD;              break;
          case RC_UNAUTH:           i=IDX_UNAUTH;           break;
          case RC_PAYMENTREQ:       i=IDX_PAYMENTREQ;       break;
          case RC_FORBIDDEN:        i=IDX_FORBIDDEN;        break;
          case RC_NOTFOUND:         i=IDX_NOTFOUND;         break;
          case RC_METHODNOTALLOWED: i=IDX_METHODNOTALLOWED; break;
          case RC_NOTACCEPTABLE:    i=IDX_NOTACCEPTABLE;    break;
          case RC_PROXYAUTHREQ:     i=IDX_PROXYAUTHREQ;     break;
          case RC_TIMEOUT:          i=IDX_TIMEOUT;          break;
          case RC_CONFLICT:         i=IDX_CONFLICT;         break;
          case RC_GONE:             i=IDX_GONE;             break;
          case RC_LENGTHREQ:        i=IDX_LENGTHREQ;        break;
          case RC_PREFAILED:        i=IDX_PREFAILED;        break;
          case RC_REQENTTOOLARGE:   i=IDX_REQENTTOOLARGE;   break;
          case RC_REQURITOOLARGE:   i=IDX_REQURITOOLARGE;   break;
          case RC_UNSUPMEDIATYPE:   i=IDX_UNSUPMEDIATYPE;   break;
	  case RC_RNGNOTSATISFIABLE:i=IDX_RNGNOTSATISFIABLE;break;
	  case RC_EXPECTATIONFAILED:i=IDX_EXPECTATIONFAILED;break;
          case RC_SERVERERR:        i=IDX_SERVERERR;        break;
          case RC_NOTIMPLEMENTED:   i=IDX_NOTIMPLEMENTED;   break;
          case RC_BADGATEWAY:       i=IDX_BADGATEWAY;       break;
          case RC_UNAVAIL:          i=IDX_UNAVAIL;          break;
          case RC_GATEWAYTIMEOUT:   i=IDX_GATEWAYTIMEOUT;   break;
          case RC_BADHTTPVER:       i=IDX_BADHTTPVER;       break;
          default:                  i=IDX_UNDEFINED;        break;
         }
         response[i].count++;

         /* now save in the various hash tables... */
         if (log_rec.resp_code==RC_OK || log_rec.resp_code==RC_PARTIALCONTENT)
            i=1; else i=0;
         
         /* URL/ident hash table (only if valid response code) */
         if ((log_rec.resp_code==RC_OK)||(log_rec.resp_code==RC_NOMOD)||
             (log_rec.resp_code==RC_PARTIALCONTENT))
         {
            /* URL hash table */
            if (put_unode(log_rec.url,OBJ_REG,(u_long)1,
                log_rec.xfer_size,&t_url,(u_long)0,(u_long)0,um_htab))
            {
               if (verbose)
               /* Error adding URL node, skipping ... */
               fprintf(stderr,"%s %s\n", msg_nomem_u, log_rec.url);
            }

            /* ident (username) hash table */
            if (put_inode(log_rec.ident,OBJ_REG,
                1,(u_long)i,log_rec.xfer_size,&t_user,
                0,rec_tstamp,im_htab))
            {
               if (verbose)
               /* Error adding ident node, skipping .... */
               fprintf(stderr,"%s %s\n", msg_nomem_i, log_rec.ident);
            }
         }

         /* referrer hash table */
         if (ntop_refs)
         {
            if (log_rec.refer[0]!='\0')
             if (put_rnode(log_rec.refer,OBJ_REG,(u_long)1,&t_ref,rm_htab))
             {
              if (verbose)
              fprintf(stderr,"%s %s\n", msg_nomem_r, log_rec.refer);
             }
         }

         /* hostname (site) hash table - daily */
         if (put_hnode(log_rec.hostname,OBJ_REG,
             1,(u_long)i,log_rec.xfer_size,&dt_site,
             0,rec_tstamp,"",sd_htab))
         {
            if (verbose)
            /* Error adding host node (daily), skipping .... */
            fprintf(stderr,"%s %s\n",msg_nomem_dh, log_rec.hostname);
         }

         /* hostname (site) hash table - monthly */
         if (put_hnode(log_rec.hostname,OBJ_REG,
             1,(u_long)i,log_rec.xfer_size,&t_site,
             0,rec_tstamp,"",sm_htab))
         {
            if (verbose)
            /* Error adding host node (monthly), skipping .... */
            fprintf(stderr,"%s %s\n", msg_nomem_mh, log_rec.hostname);
         }

         /* user agent hash table */
         if (ntop_agents)
         {
            if (log_rec.agent[0]!='\0')
             if (put_anode(log_rec.agent,OBJ_REG,(u_long)1,&t_agent,am_htab))
             {
              if (verbose)
              fprintf(stderr,"%s %s\n", msg_nomem_a, log_rec.agent);
             }
         }

         /* bump monthly/daily/hourly totals        */
         t_hit++; ht_hit++;                         /* daily/hourly hits    */
         t_xfer += log_rec.xfer_size;               /* total xfer size      */
         tm_xfer[rec_day-1] += log_rec.xfer_size;   /* daily xfer total     */
         tm_hit[rec_day-1]++;                       /* daily hits total     */
         th_xfer[rec_hour] += log_rec.xfer_size;    /* hourly xfer total    */
         th_hit[rec_hour]++;                        /* hourly hits total    */
   
         /* if RC_OK, increase file counters */
         if (log_rec.resp_code == RC_OK)
         {
            t_file++;
            tm_file[rec_day-1]++;
            th_file[rec_hour]++;
         }

         /* Pages (pageview) calculation */
         if (ispage(log_rec.url))
         {
            t_page++;
            tm_page[rec_day-1]++;
            th_page[rec_hour]++;

            /* do search string stuff if needed     */
            if (ntop_search) srch_string(log_rec.srchstr);
         }

         /*********************************************/
         /* RECORD PROCESSED - DO GROUPS HERE         */ 
         /*********************************************/

         /* URL Grouping */
         if ( (cp1=isinglist(group_urls,log_rec.url))!=NULL)
         {
            if (put_unode(cp1,OBJ_GRP,(u_long)1,log_rec.xfer_size,
                &ul_bogus,(u_long)0,(u_long)0,um_htab))
            {
               if (verbose)
               /* Error adding URL node, skipping ... */
               fprintf(stderr,"%s %s\n", msg_nomem_u, cp1);
            }
         }

         /* Site Grouping */
         if ( (cp1=isinglist(group_sites,log_rec.hostname))!=NULL)
         {
            if (put_hnode(cp1,OBJ_GRP,1,(u_long)(log_rec.resp_code==RC_OK)?1:0,
                          log_rec.xfer_size,&ul_bogus,
                          0,rec_tstamp,"",sm_htab))
            {
               if (verbose)
               /* Error adding Site node, skipping ... */
               fprintf(stderr,"%s %s\n", msg_nomem_mh, cp1);
            }
         }
         else
         {
            /* Domain Grouping */
            if (group_domains)
            {
               cp1 = get_domain(log_rec.hostname);
               if (cp1 != NULL)
               {
                  if (put_hnode(cp1,OBJ_GRP,1,
                      (u_long)(log_rec.resp_code==RC_OK)?1:0,
                      log_rec.xfer_size,&ul_bogus,
                      0,rec_tstamp,"",sm_htab))
                  {
                     if (verbose)
                     /* Error adding Site node, skipping ... */
                     fprintf(stderr,"%s %s\n", msg_nomem_mh, cp1);
                  }
               }
            }
         }

         /* Referrer Grouping */
         if ( (cp1=isinglist(group_refs,log_rec.refer))!=NULL)
         {
            if (put_rnode(cp1,OBJ_GRP,(u_long)1,&ul_bogus,rm_htab))
            {
               if (verbose)
               /* Error adding Referrer node, skipping ... */
               fprintf(stderr,"%s %s\n", msg_nomem_r, cp1);
            }
         }

         /* User Agent Grouping */
         if ( (cp1=isinglist(group_agents,log_rec.agent))!=NULL)
         {
            if (put_anode(cp1,OBJ_GRP,(u_long)1,&ul_bogus,am_htab))
            {
               if (verbose)
               /* Error adding User Agent node, skipping ... */
               fprintf(stderr,"%s %s\n", msg_nomem_a, cp1);
            }
         }

         /* Ident (username) Grouping */
         if ( (cp1=isinglist(group_users,log_rec.ident))!=NULL)
         {
            if (put_inode(cp1,OBJ_GRP,1,(u_long)(log_rec.resp_code==RC_OK)?1:0,
                          log_rec.xfer_size,&ul_bogus,
                          0,rec_tstamp,im_htab))
            {
               if (verbose)
               /* Error adding Username node, skipping ... */
               fprintf(stderr,"%s %s\n", msg_nomem_i, cp1);
            }
         }
      }

      /*********************************************/
      /* BAD RECORD                                */
      /*********************************************/

      else
      {
         /* If first record, check if stupid Netscape header stuff      */
         if ( (total_rec==1) && (strncmp(buffer,"format=",7)==0) )
         {
            /* Skipping Netscape header record */
            if (verbose>1) printf("%s\n",msg_ign_nscp);
            /* count it as ignored... */
            total_ignore++;
         }
         else
         {
            /* really bad record... */
            total_bad++;
            if (verbose)
            {
               fprintf(stderr,"%s (%lu)",msg_bad_rec,total_rec);
               if (debug_mode) fprintf(stderr,":\n%s\n",tmp_buf);
               else fprintf(stderr,"\n");
            }
         }
      }
   }

   /*********************************************/
   /* DONE READING LOG FILE - final processing  */
   /*********************************************/

   /* close log file if needed */
   if (gz_log) gzclose(gzlog_fp);
   else if (log_fname) fclose(log_fp);

   if (good_rec)                             /* were any good records?   */
   {
      tm_site[cur_day-1]=dt_site;            /* If yes, clean up a bit   */
      tm_visit[cur_day-1]=tot_visit(sd_htab);
      t_visit=tot_visit(sm_htab);
      if (ht_hit > mh_hit) mh_hit = ht_hit;

      if (total_rec > (total_ignore+total_bad)) /* did we process any?   */
      {
         if (incremental)
         {
            if (save_state())                /* incremental stuff        */
            {
               /* Error: Unable to save current run data */
               if (verbose) fprintf(stderr,"%s\n",msg_data_err);
               unlink(state_fname);
            }
         }
         month_update_exit(rec_tstamp);      /* calculate exit pages     */
    //write_month_html();                 /* write monthly HTML file  */
		write_month_xml();
        write_main_xml();                 /* write main HTML file     */
	//write_main_index();
         put_history();                      /* write history            */
      }

      end_time = times(&mytms);              /* display timing totals?   */
      if (time_me || (verbose>1))
      {
         printf("%lu %s ",total_rec, msg_records);
         if (total_ignore)
         {
            printf("(%lu %s",total_ignore,msg_ignored);
            if (total_bad) printf(", %lu %s) ",total_bad,msg_bad);
               else        printf(") ");
         }
         else if (total_bad) printf("(%lu %s) ",total_bad,msg_bad);

         /* get processing time (end-start) */
         temp_time = (float)(end_time-start_time)/CLK_TCK;
         printf("%s %.2f %s", msg_in, temp_time, msg_seconds);

         /* calculate records per second */
         if (temp_time)
           i=( (int)( (float)total_rec/temp_time ) );
         else i=0;

         if ( (i>0) && (i<=total_rec) ) printf(", %d/sec\n", i);
            else  printf("\n");
      }

#ifdef USE_DNS
      if (dns_db) close_cache();
#endif

      /* Whew, all done! Exit with completion status (0) */
      exit(0);
   }
   else
   {
      /* No valid records found... exit with error (1) */
      if (verbose) printf("%s\n",msg_no_vrec);
      exit(1);
   }
}

/*********************************************/
/* GET_CONFIG - get configuration file info  */
/*********************************************/

void get_config(char *fname)
{
   char *kwords[]= { "Undefined",         /* 0 = undefined keyword       0  */
                     "OutputDir",         /* Output directory            1  */
                     "LogFile",           /* Log file to use for input   2  */
                     "ReportTitle",       /* Title for reports           3  */
                     "HostName",          /* Hostname to use             4  */
                     "IgnoreHist",        /* Ignore history file         5  */
                     "Quiet",             /* Run in quiet mode           6  */
                     "TimeMe",            /* Produce timing results      7  */
                     "Debug",             /* Produce debug information   8  */
                     "HourlyGraph",       /* Hourly stats graph          9  */
                     "HourlyStats",       /* Hourly stats table         10  */
                     "TopSites",          /* Top sites                  11  */
                     "TopURLs",           /* Top URL's                  12  */
                     "TopReferrers",      /* Top Referrers              13  */
                     "TopAgents",         /* Top User Agents            14  */
                     "TopCountries",      /* Top Countries              15  */
                     "HideSite",          /* Sites to hide              16  */
                     "HideURL",           /* URL's to hide              17  */
                     "HideReferrer",      /* Referrers to hide          18  */
                     "HideAgent",         /* User Agents to hide        19  */
                     "IndexAlias",        /* Aliases for index.html     20  */
                     "HTMLHead",          /* HTML Top1 code             21  */
                     "HTMLPost",          /* HTML Top2 code             22  */
                     "HTMLTail",          /* HTML Tail code             23  */
                     "MangleAgents",      /* Mangle User Agents         24  */
                     "IgnoreSite",        /* Sites to ignore            25  */
                     "IgnoreURL",         /* Url's to ignore            26  */
                     "IgnoreReferrer",    /* Referrers to ignore        27  */
                     "IgnoreAgent",       /* User Agents to ignore      28  */
                     "ReallyQuiet",       /* Dont display ANY messages  29  */
                     "GMTTime",           /* Local or UTC time?         30  */
                     "GroupURL",          /* Group URL's                31  */
                     "GroupSite",         /* Group Sites                32  */
                     "GroupReferrer",     /* Group Referrers            33  */
                     "GroupAgent",        /* Group Agents               34  */
                     "GroupShading",      /* Shade Grouped entries      35  */
                     "GroupHighlight",    /* BOLD Grouped entries       36  */
                     "Incremental",       /* Incremental runs           37  */
                     "IncrementalName",   /* Filename for state data    38  */
                     "HistoryName",       /* Filename for history data  39  */
                     "HTMLExtension",     /* HTML filename extension    40  */
                     "HTMLPre",           /* HTML code at beginning     41  */
                     "HTMLBody",          /* HTML body code             42  */
                     "HTMLEnd",           /* HTML code at end           43  */
                     "UseHTTPS",          /* Use https:// on URL's      44  */
                     "IncludeSite",       /* Sites to always include    45  */
                     "IncludeURL",        /* URL's to always include    46  */
                     "IncludeReferrer",   /* Referrers to include       47  */
                     "IncludeAgent",      /* User Agents to include     48  */
                     "PageType",          /* Page Type (pageview)       49  */
                     "VisitTimeout",      /* Visit timeout (seconds)    50  */
                     "GraphLegend",       /* Graph Legends (yes/no)     51  */
                     "GraphLines",        /* Graph Lines (0=none)       52  */
                     "FoldSeqErr",        /* Fold sequence errors       53  */
                     "CountryGraph",      /* Display ctry graph (0=no)  54  */
                     "TopKSites",         /* Top sites (by KBytes)      55  */
                     "TopKURLs",          /* Top URL's (by KBytes)      56  */
                     "TopEntry",          /* Top Entry Pages            57  */
                     "TopExit",           /* Top Exit Pages             58  */
                     "TopSearch",         /* Top Search Strings         59  */
                     "LogType",           /* Log Type (clf/ftp/squid)   60  */
                     "SearchEngine",      /* SearchEngine strings       61  */
                     "GroupDomains",      /* Group domains (n=level)    62  */
                     "HideAllSites",      /* Hide ind. sites (0=no)     63  */
                     "AllSites",          /* List all sites?            64  */
                     "AllURLs",           /* List all URLs?             65  */
                     "AllReferrers",      /* List all Referrers?        66  */
                     "AllAgents",         /* List all User Agents?      67  */
                     "AllSearchStr",      /* List all Search Strings?   68  */
                     "AllUsers",          /* List all Users?            69  */
                     "TopUsers",          /* Top Usernames to show      70  */
                     "HideUser",          /* Usernames to hide          71  */
                     "IgnoreUser",        /* Usernames to ignore        72  */
                     "IncludeUser",       /* Usernames to include       73  */
                     "GroupUser",         /* Usernames to group         74  */
                     "DumpPath",          /* Path for dump files        75  */
                     "DumpExtension",     /* Dump filename extension    76  */
                     "DumpHeader",        /* Dump header as first rec?  77  */
                     "DumpSites",         /* Dump sites tab file        78  */
                     "DumpURLs",          /* Dump urls tab file         79  */
                     "DumpReferrers",     /* Dump referrers tab file    80  */
                     "DumpAgents",        /* Dump user agents tab file  81  */
                     "DumpUsers",         /* Dump usernames tab file    82  */
                     "DumpSearchStr",     /* Dump search str tab file   83  */
                     "DNSCache",          /* DNS Cache file name        84  */
                     "DNSChildren",       /* DNS Children (0=no DNS)    85  */
                     "DailyGraph",        /* Daily Graph (0=no)         86  */
                     "DailyStats"         /* Daily Stats (0=no)         87  */
                   };

   FILE *fp;

   char buffer[BUFSIZE];
   char keyword[32];
   char value[132];
   char *cp1, *cp2;
   int  i,key;
   int	num_kwords=sizeof(kwords)/sizeof(char *);

   if ( (fp=fopen(fname,"r")) == NULL)
   {
      if (verbose)
      fprintf(stderr,"%s %s\n",msg_bad_conf,fname);
      return;
   }

   while ( (fgets(buffer,BUFSIZE,fp)) != NULL)
   {
      /* skip comments and blank lines */
      if ( (buffer[0]=='#') || isspace((int)buffer[0]) ) continue;

      /* Get keyword */
      cp1=buffer;cp2=keyword;
      while ( isalnum((int)*cp1) ) *cp2++ = *cp1++;
      *cp2='\0';

      /* Get value */
      cp2=value;
      while ( (*cp1!='\n')&&(*cp1!='\0')&&(isspace((int)*cp1)) ) cp1++;
      while ( (*cp1!='\n')&&(*cp1!='\0') ) *cp2++ = *cp1++;
      *cp2--='\0';
      while ( (isspace((int)*cp2)) && (cp2 != value) ) *cp2--='\0';

      /* check if blank keyword/value */
      if ( (keyword[0]=='\0') || (value[0]=='\0') ) continue;

      key=0;
      for (i=0;i<num_kwords;i++)
         if (!strcmp(keyword,kwords[i])) { key=i; break; }

      if (key==0) { printf("%s '%s' (%s)\n",       /* Invalid keyword       */
                    msg_bad_key,keyword,fname);
                    continue;
                  }

      switch (key)
      {
        case 1:  out_dir=save_opt(value);          break; /* OutputDir      */
        case 2:  log_fname=save_opt(value);        break; /* LogFile        */
        case 3:  msg_title=save_opt(value);        break; /* ReportTitle    */
        case 4:  hname=save_opt(value);            break; /* HostName       */
        case 5:  ignore_hist=(value[0]=='n')?0:1;  break; /* IgnoreHist     */
        case 6:  verbose=(value[0]=='n')?2:1;      break; /* Quiet          */
        case 7:  time_me=(value[0]=='n')?0:1;      break; /* TimeMe         */
        case 8:  debug_mode=(value[0]=='n')?0:1;   break; /* Debug          */
        case 9:  hourly_graph=(value[0]=='n')?0:1; break; /* HourlyGraph    */
        case 10: hourly_stats=(value[0]=='n')?0:1; break; /* HourlyStats    */
        case 11: ntop_sites = atoi(value);         break; /* TopSites       */
        case 12: ntop_urls = atoi(value);          break; /* TopURLs        */
        case 13: ntop_refs = atoi(value);          break; /* TopRefs        */
        case 14: ntop_agents = atoi(value);        break; /* TopAgents      */
        case 15: ntop_ctrys = atoi(value);         break; /* TopCountries   */
        case 16: add_nlist(value,&hidden_sites);   break; /* HideSite       */
        case 17: add_nlist(value,&hidden_urls);    break; /* HideURL        */
        case 18: add_nlist(value,&hidden_refs);    break; /* HideReferrer   */
        case 19: add_nlist(value,&hidden_agents);  break; /* HideAgent      */
        case 20: add_nlist(value,&index_alias);    break; /* IndexAlias     */
        case 21: add_nlist(value,&html_head);      break; /* HTMLHead       */
        case 22: add_nlist(value,&html_post);      break; /* HTMLPost       */
        case 23: add_nlist(value,&html_tail);      break; /* HTMLTail       */
        case 24: mangle_agent=atoi(value);         break; /* MangleAgents   */
        case 25: add_nlist(value,&ignored_sites);  break; /* IgnoreSite     */
        case 26: add_nlist(value,&ignored_urls);   break; /* IgnoreURL      */
        case 27: add_nlist(value,&ignored_refs);   break; /* IgnoreReferrer */
        case 28: add_nlist(value,&ignored_agents); break; /* IgnoreAgent    */
        case 29: if (value[0]=='y') verbose=0;     break; /* ReallyQuiet    */
        case 30: local_time=(value[0]=='y')?0:1;   break; /* GMTTime        */
        case 31: add_glist(value,&group_urls);     break; /* GroupURL       */
        case 32: add_glist(value,&group_sites);    break; /* GroupSite      */
        case 33: add_glist(value,&group_refs);     break; /* GroupReferrer  */
        case 34: add_glist(value,&group_agents);   break; /* GroupAgent     */
        case 35: shade_groups=(value[0]=='y')?1:0; break; /* GroupShading   */
        case 36: hlite_groups=(value[0]=='y')?1:0; break; /* GroupHighlight */
        case 37: incremental=(value[0]=='y')?1:0;  break; /* Incremental    */
        case 38: state_fname=save_opt(value);      break; /* State FName    */
        case 39: hist_fname=save_opt(value);       break; /* History FName  */
        case 40: html_ext=save_opt(value);         break; /* HTML extension */
        case 41: add_nlist(value,&html_pre);       break; /* HTML Pre code  */
        case 42: add_nlist(value,&html_body);      break; /* HTML Body code */
        case 43: add_nlist(value,&html_end);       break; /* HTML End code  */
        case 44: use_https=(value[0]=='y')?1:0;    break; /* Use https://   */
        case 45: add_nlist(value,&include_sites);  break; /* IncludeSite    */
        case 46: add_nlist(value,&include_urls);   break; /* IncludeURL     */
        case 47: add_nlist(value,&include_refs);   break; /* IncludeReferrer*/
        case 48: add_nlist(value,&include_agents); break; /* IncludeAgent   */
        case 49: add_nlist(value,&page_type);      break; /* PageType       */
        case 50: visit_timeout=atoi(value);        break; /* VisitTimeout   */
        case 51: graph_legend=(value[0]=='y')?1:0; break; /* GraphLegend    */
        case 52: graph_lines = atoi(value);        break; /* GraphLines     */
        case 53: fold_seq_err=(value[0]=='y')?1:0; break; /* FoldSeqErr     */
        case 54: ctry_graph=(value[0]=='y')?1:0;   break; /* CountryGraph   */
        case 55: ntop_sitesK = atoi(value);        break; /* TopKSites (KB) */
        case 56: ntop_urlsK  = atoi(value);        break; /* TopKUrls (KB)  */
        case 57: ntop_entry  = atoi(value);        break; /* Top Entry pgs  */
        case 58: ntop_exit   = atoi(value);        break; /* Top Exit pages */
        case 59: ntop_search = atoi(value);        break; /* Top Search pgs */
        case 60: log_type=(value[0]=='f')?
                 LOG_FTP:((value[0]=='s')?
                 LOG_SQUID:LOG_CLF);               break; /* LogType        */
        case 61: add_glist(value,&search_list);    break; /* SearchEngine   */
        case 62: group_domains=atoi(value);        break; /* GroupDomains   */
        case 63: hide_sites=(value[0]=='y')?1:0;   break; /* HideAllSites   */
        case 64: all_sites=(value[0]=='y')?1:0;    break; /* All Sites?     */
        case 65: all_urls=(value[0]=='y')?1:0;     break; /* All URL's?     */
        case 66: all_refs=(value[0]=='y')?1:0;     break; /* All Refs       */
        case 67: all_agents=(value[0]=='y')?1:0;   break; /* All Agents?    */
        case 68: all_search=(value[0]=='y')?1:0;   break; /* All Srch str   */
        case 69: all_users=(value[0]=='y')?1:0;    break; /* All Users?     */
        case 70: ntop_users=atoi(value);           break; /* TopUsers       */
        case 71: add_nlist(value,&hidden_users);   break; /* HideUser       */
        case 72: add_nlist(value,&ignored_users);  break; /* IgnoreUser     */
        case 73: add_nlist(value,&include_users);  break; /* IncludeUser    */
        case 74: add_glist(value,&group_users);    break; /* GroupUser      */
        case 75: dump_path=save_opt(value);        break; /* DumpPath       */
        case 76: dump_ext=save_opt(value);         break; /* Dumpfile ext   */
        case 77: dump_header=(value[0]=='y')?1:0;  break; /* DumpHeader?    */
        case 78: dump_sites=(value[0]=='y')?1:0;   break; /* DumpSites?     */
        case 79: dump_urls=(value[0]=='y')?1:0;    break; /* DumpURLs?      */
        case 80: dump_refs=(value[0]=='y')?1:0;    break; /* DumpReferrers? */
        case 81: dump_agents=(value[0]=='y')?1:0;  break; /* DumpAgents?    */
        case 82: dump_users=(value[0]=='y')?1:0;   break; /* DumpUsers?     */
        case 83: dump_search=(value[0]=='y')?1:0;  break; /* DumpSrchStrs?  */
#ifdef USE_DNS
        case 84: dns_cache=save_opt(value);        break; /* DNSCache fname */
        case 85: dns_children=atoi(value);         break; /* DNSChildren    */
#else
        case 84: /* Disable DNSCache and DNSChildren if DNS is not enabled  */
        case 85: printf("%s '%s' (%s)\n",msg_bad_key,keyword,fname); break;
#endif  /* USE_DNS */
        case 86: daily_graph=(value[0]=='n')?0:1; break;  /* HourlyGraph    */
        case 87: daily_stats=(value[0]=='n')?0:1; break;  /* HourlyStats    */
      }
   }
   fclose(fp);
}

/*********************************************/
/* SAVE_OPT - save option from config file   */
/*********************************************/

static char *save_opt(char *str)
{
   char *cp1;

   if ( (cp1=malloc(strlen(str)+1))==NULL) return NULL;

   strcpy(cp1,str);
   return cp1;
}

/*********************************************/
/* CLEAR_MONTH - initalize monthly stuff     */
/*********************************************/

void clear_month()
{
   int i;

   init_counters();                  /* reset monthly counters  */
   del_htabs();                      /* clear hash tables       */
   if (ntop_ctrys!=0 ) for (i=0;i<ntop_ctrys;i++)  top_ctrys[i]=NULL;
}

/*********************************************/
/* INIT_COUNTERS - prep counters for use     */
/*********************************************/

void init_counters()
{
   int i;
   for (i=0;i<TOTAL_RC;i++) response[i].count = 0;
   for (i=0;i<31;i++)  /* monthly totals      */
   {
    tm_xfer[i]=0.0;
    tm_hit[i]=tm_file[i]=tm_site[i]=tm_page[i]=tm_visit[i]=0;
   }
   for (i=0;i<24;i++)  /* hourly totals       */
   {
      th_hit[i]=th_file[i]=th_page[i]=0;
      th_xfer[i]=0.0;
   }
   for (i=0;ctry[i].desc;i++) /* country totals */
   {
      ctry[i].count=0;
      ctry[i].files=0;
      ctry[i].xfer=0;
   }
   t_hit=t_file=t_site=t_url=t_ref=t_agent=t_page=t_visit=t_user=0;
   t_xfer=0.0;
   mh_hit = dt_site = 0;
   f_day=l_day=1;
}

/*********************************************/
/* PRINT_OPTS - print command line options   */
/*********************************************/

void print_opts(char *pname)
{
   int i;

   printf("%s: %s %s\n",h_usage1,pname,h_usage2);
   for (i=0;h_msg[i];i++) printf("%s\n",h_msg[i]);
   exit(1);
}

/*********************************************/
/* PRINT_VERSION                             */
/*********************************************/

void print_version()
{
 uname(&system_info);
 printf("Webalizer V%s-%s (%s %s) %s\n%s\n",
    version,editlvl,
    system_info.sysname,system_info.release,
    language,copyright);
 if (debug_mode)
 {
    printf("Mod date: %s  Options: ",moddate);
#ifdef USE_DNS
    printf("DNS ");
#else
    printf("none");
#endif
    printf("\nDefault config dir: %s\n\n",ETCDIR);
 }
 else printf("\n");
 exit(1);
}

/*********************************************/
/* CUR_TIME - return date/time as a string   */
/*********************************************/

char *cur_time()
{
   /* get system time */
   now = time(NULL);
   /* convert to timestamp string */
   if (local_time)
      strftime(timestamp,sizeof(timestamp),"%d-%b-%Y %H:%M %Z",
            localtime(&now));
   else
      strftime(timestamp,sizeof(timestamp),"%d-%b-%Y %H:%M GMT",
            gmtime(&now));

   return timestamp;
}

/*********************************************/
/* ISPAGE - determine if an HTML page or not */
/*********************************************/

int ispage(char *str)
{
   char *cp1, *cp2;

   cp1=cp2=str;
   while (*cp1!='\0') { if (*cp1=='.') cp2=cp1; cp1++; }
   if ((cp2++==str)||(*(--cp1)=='/')) return 1;
   else return (isinlist(page_type,cp2)!=NULL);
}

/*********************************************/
/* ISURLCHAR - checks for valid URL chars    */
/*********************************************/

int isurlchar(unsigned char ch)
{
   if (isalnum((int)ch)) return 1;           /* allow letters, numbers...    */
   if (ch > 127) return 1;                   /* allow extended chars...      */
   return (strchr(":/\\.,' *-+_@~()[]",ch)!=NULL); /* and a few special ones */
}

/*********************************************/
/* CTRY_IDX - create unique # from domain    */
/*********************************************/

u_long ctry_idx(char *str)
{
   int i=strlen(str),j=0;
   u_long idx=0;
   char *cp1=str+i;
   for (;i>0;i--) { idx+=((*--cp1-'a'+1)<<j); j+=5; }
   return idx;
}

/*********************************************/
/* FROM_HEX - convert hex char to decimal    */
/*********************************************/

char from_hex(char c)                           /* convert hex to dec      */
{
   c = (c>='0'&&c<='9')?c-'0':                  /* 0-9?                    */
       (c>='A'&&c<='F')?c-'A'+10:               /* A-F?                    */
       c - 'a' + 10;                            /* lowercase...            */
   return (c<0||c>15)?0:c;                      /* return 0 if bad...      */
}

/*********************************************/
/* UNESCAPE - convert escape seqs to chars   */
/*********************************************/

char *unescape(char *str)
{
   unsigned char *cp1=str;                      /* force unsigned so we    */
   unsigned char *cp2=str;                      /* can do > 127            */

   if (!str) return NULL;                       /* make sure strings valid */

   while (*cp1)
   {
      if (*cp1=='%')                            /* Found an escape?        */
      {
         cp1++;
         if (isxdigit(*cp1))                    /* ensure a hex digit      */
         {
            if (*cp1) *cp2=from_hex(*cp1++)*16; /* convert hex to an ascii */
            if (*cp1) *cp2+=from_hex(*cp1);     /* (hopefully) character   */
            if ((*cp2<32)||(*cp2==127)) *cp2='_'; /* make '_' if its bad   */
            if (*cp1) cp2++; cp1++;
         }
         else *cp2++='%';
      }
      else *cp2++ = *cp1++;                     /* if not, just continue   */
   }
   *cp2=*cp1;                                   /* don't forget terminator */
   return str;                                  /* return the string       */
}

/*********************************************/
/* SRCH_STRING - get search strings from ref */
/*********************************************/

void srch_string(char *ptr)
{
   /* ptr should point to unescaped query string */
   char tmpbuf[BUFSIZE];
   char srch[80]="";
   unsigned char *cp1, *cp2, *cps;
   int  sp_flg=0;

   /* Check if search engine referrer or return  */
   if ( (cps=isinglist(search_list,log_rec.refer))==NULL) return; 

   /* Try to find query variable */
   srch[0]='?'; strcpy(&srch[1],cps);              /* First, try "?..."      */
   if ((cp1=strstr(ptr,srch))==NULL)
   {
      srch[0]='&';                                 /* Next, try "&..."       */
      if ((cp1=strstr(ptr,srch))==NULL) return;    /* If not found, split... */
   }
   cp2=tmpbuf;
   while (*cp1!='=' && *cp1!=0) cp1++; if (*cp1!=0) cp1++;
   while (*cp1!='&' && *cp1!=0)
   {
      if (*cp1=='"' || *cp1==',' || *cp1=='?')
          { cp1++; continue; }                         /* skip bad ones..    */
      else
      {
         if (*cp1=='+') *cp1=' ';                      /* change + to space  */
         if (sp_flg && *cp1==' ') { cp1++; continue; } /* compress spaces    */
         if (*cp1==' ') sp_flg=1; else sp_flg=0;       /* (flag spaces here) */
         *cp2++=tolower(*cp1);                         /* normal character   */
         cp1++;
      }
   }
   *cp2=0; cp2=tmpbuf;
   if (tmpbuf[0]=='?') tmpbuf[0]=' ';                  /* format fix ?       */
   while( *cp2!=0 && isspace(*cp2) ) cp2++;            /* skip leading sps.  */
   if (*cp2==0) return;

   /* any trailing spaces? */
   cp1=cp2+strlen(cp2)-1;
   while (cp1!=cp2) if (isspace(*cp1)) *cp1--='\0'; else break;

   /* strip invalid chars */
   cp1=cp2;
   while (*cp1!=0) { if ((*cp1<32)||(*cp1==127)) *cp1='_'; cp1++; }

   if (put_snode(cp2,(u_long)1,sr_htab))
   {
      if (verbose)
      /* Error adding search string node, skipping .... */
      fprintf(stderr,"%s %s\n", msg_nomem_sc, tmpbuf);
   }
   return;
}

/*********************************************/
/* GET_DOMAIN - Get domain portion of host   */
/*********************************************/

char *get_domain(char *str)
{
   char *cp;
   int  i=group_domains+1;

   cp = str+strlen(str)-1;
   if (isdigit((int)*cp)) return NULL;   /* ignore IP addresses */

   while (cp!=str)
   {
      if (*cp=='.')
         if (!(--i)) return ++cp;
      cp--;
   }
   return cp;
}

/*********************************************/
/* OUR_GZGETS - enhanced gzgets for log only */
/*********************************************/

char *our_gzgets(gzFile fp, char *buf, int size)
{
   char *out_cp=buf;      /* point to output */
   while (1)
   {
      if (f_cp>(f_buf+f_end-1))     /* load? */
      {
         f_end=gzread(fp, f_buf, GZ_BUFSIZE);
         if (f_end<=0) return Z_NULL;
         f_cp=f_buf;
      }

      if (--size)                   /* more? */
      {
         *out_cp++ = *f_cp;
         if (*f_cp++ == '\n') { *out_cp='\0'; return buf; }
      }
      else { *out_cp='\0'; return buf; }
   }
}

/*****************************************************************/
/*                                                               */
/* JDATE  - Julian date calculator                               */
/*                                                               */
/* Calculates the number of days since Jan 1, 0000.              */
/*                                                               */
/* Originally written by Bradford L. Barrett (03/17/1988)        */
/* Returns an unsigned long value representing the number of     */
/* days since January 1, 0000.                                   */
/*                                                               */
/* Note: Due to the changes made by Pope Gregory XIII in the     */
/*       16th Centyry (Feb 24, 1582), dates before 1583 will     */
/*       not return a truely accurate number (will be at least   */
/*       10 days off).  Somehow, I don't think this will         */
/*       present much of a problem for most situations :)        */
/*                                                               */
/* Usage: days = jdate(day, month, year)                         */
/*                                                               */
/* The number returned is adjusted by 5 to facilitate day of     */
/* week calculations.  The mod of the returned value gives the   */
/* day of the week the date is.  (ie: dow = days % 7 ) where     */
/* dow will return 0=Sunday, 1=Monday, 2=Tuesday, etc...         */
/*                                                               */
/*****************************************************************/

u_long jdate( int day, int month, int year )
{
   u_long days;                      /* value returned */
   int mtable[] = {0,31,59,90,120,151,181,212,243,273,304,334};

   /* First, calculate base number including leap and Centenial year stuff */

   days=(((u_long)year*365)+day+mtable[month-1]+
           ((year+4)/4) - ((year/100)-(year/400)));

   /* now adjust for leap year before March 1st */

   if ((year % 4 == 0) && !((year % 100 == 0) &&
       (year % 400 != 0)) && (month < 3))
   --days;

   /* done, return with calculated value */

   return(days+5);
}
