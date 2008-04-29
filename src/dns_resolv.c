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

    dns_resolv.c - based on the dns-resolver code submitted by
                   Henning P. Schmiedehausen <hps@tanstaafl.de>
                   and modified for inclusion in the Webalizer
                   directly.  Enabled with -DUSE_DNS.

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

/* Need socket header? */
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

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

#ifdef USE_DNS                   /* skip everything in this file if no DNS */

#include <netinet/in.h>          /* include stuff we need for dns lookups, */
#include <arpa/inet.h>           /* DB access, file control, etc...        */
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <sys/signal.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>

#ifdef HAVE_DB_185_H
#include <db_185.h>                            /* on my RH6.0 system ?!?   */
#else
#include <db.h>                                /* DB header ****************/
#endif /* HAVE_DB_185_H */

#include "webalizer.h"                         /* main header              */
#include "lang.h"                              /* language declares        */
#include "hashtab.h"                           /* hash table functions     */
#include "parser.h"                            /* log parser functions     */
#include "dns_resolv.h"                        /* our header               */

/* local data */

#ifndef HAVE_ERRNO_H
int      errno;                                /* errno for those in need  */
#endif

DB       *dns_db   = NULL;                     /* DNS cache database       */
int      dns_fd    = 0;

struct   dns_child child[MAXCHILD];            /* DNS child pipe data      */

DNODEPTR host_table[MAXHASH];                  /* hostname/ip hash table   */

char     buffer[BUFSIZE];                      /* log file record buffer   */
char     tmp_buf[BUFSIZE];                     /* used to temp save above  */
struct   utsname system_info;                  /* system info structure    */

int      raiseSigChild = 1;

time_t runtime;
time_t start_time, end_time;
float  temp_time;

extern char *our_gzgets(gzFile, char *, int);  /* external our_gzgets func */

/* internal function prototypes */

static void process_list(DNODEPTR);
static void sigChild(int);
static void db_put(char *, char *, int);
void   set_fl(int, int);
void   clr_fl(int, int);

/*********************************************/
/* RESOLVE_DNS - lookup IP in cache          */
/*********************************************/

void resolve_dns(struct log_struct *log_rec)
{
   DBT    query, response;
   /* aligned dnsRecord to prevent Solaris from doing a dump */
   /* (not found in debugger, as it can dereference it :(    */
   struct dnsRecord alignedRecord;

   if (!dns_db) return;   /* ensure we have a dns db */

   query.data = log_rec->hostname;
   query.size = strlen(log_rec->hostname);

   if (debug_mode) fprintf(stderr,"Checking %s...", log_rec->hostname);

   switch((dns_db->get)(dns_db, &query, &response, 0))
   {
      case -1: if (debug_mode) fprintf(stderr," Lookup error\n"); break;
      case  1: if (debug_mode) fprintf(stderr," not found\n");    break;
      case  0:
      {
         memcpy(&alignedRecord, response.data, sizeof(struct dnsRecord));
         strncpy (log_rec->hostname,
                  ((struct dnsRecord *)response.data)->hostName,
                  MAXHOST);
         log_rec->hostname[MAXHOST-1]=0;
         if (debug_mode)
            fprintf(stderr," found: %s (%ld)\n",
             log_rec->hostname, alignedRecord.timeStamp);
         break;
      }
      default: if (debug_mode) fprintf(stderr," Invalid response\n");
   }
}

/*********************************************/
/* DNS_RESOLVER - read log and lookup IP's   */
/*********************************************/

int dns_resolver(void *log_fp)
{
   DNODEPTR  h_entries;
   DNODEPTR  l_list = NULL;

   int       i;
   int       save_verbose=verbose;

   u_long    listEntries = 0;

   struct sigaction sigPipeAction;
   struct stat dbStat;
   struct tms  mytms;
   /* aligned dnsRecord to prevent Solaris from doing a dump */
   /* (not found in debugger, as it can dereference it :(    */
   struct dnsRecord alignedRecord;

   struct    flock tmp_flock;

   tmp_flock.l_whence=SEEK_SET;    /* default flock fields */
   tmp_flock.l_start=0;
   tmp_flock.l_len=0;
   tmp_flock.l_pid=0;

   time(&runtime);
   start_time = times(&mytms);   /* get start time */

   /* minimal sanity check on it */
   if(stat(dns_cache, &dbStat) < 0)
   {
      if(errno != ENOENT)
      {
         dns_cache=NULL;
         dns_db=NULL; return 0;  /* disable cache */
      }
   }
   else
   {
      if(!dbStat.st_size)  /* bogus file, probably from a crash */
      {
         unlink(dns_cache);  /* remove it so we can recreate... */
      }
   }
  
   /* open cache file */
   if(!(dns_db = dbopen(dns_cache, O_RDWR|O_CREAT, 0664, DB_HASH, NULL)))
   {
      /* Error: Unable to open DNS cache file <filename> */
      if (verbose) fprintf(stderr,"%s %s\n",msg_dns_nodb,dns_cache);
      dns_cache=NULL;
      dns_db=NULL;
      return 0;                  /* disable cache */
   }

   /* get file descriptor */
   dns_fd = dns_db->fd(dns_db);

   tmp_flock.l_type=F_WRLCK;                    /* set read/write lock type */
   if (fcntl(dns_fd,F_SETLK,&tmp_flock) < 0)    /* and barf if we cant lock */
   {
      /* Error: Unable to lock DNS cache file <filename> */
      if (verbose) fprintf(stderr,"%s %s\n",msg_dns_nolk,dns_cache);
      dns_db->close(dns_db);
      dns_cache=NULL;
      dns_db=NULL;
      return 0;                  /* disable cache */
   }

   /* Setup signal handlers */
   sigPipeAction.sa_handler = SIG_IGN;
   sigPipeAction.sa_flags   = SA_RESTART;
   sigemptyset(&sigPipeAction.sa_mask);

   sigaction(SIGPIPE, &sigPipeAction, NULL);

   /* disable warnings/errors for this run... */
   verbose=0;

   /* Main loop to read log records (either regular or zipped) */
   while ( (gz_log)?(our_gzgets((gzFile)log_fp,buffer,BUFSIZE) != Z_NULL):
           (fgets(buffer,BUFSIZE,log_fname?(FILE *)log_fp:stdin) != NULL))
   {
      if (strlen(buffer) == (BUFSIZE-1))
      {
         /* get the rest of the record */
         while ( (gz_log)?(our_gzgets((gzFile)log_fp,buffer,BUFSIZE)!=Z_NULL):
                 (fgets(buffer,BUFSIZE,log_fname?(FILE *)log_fp:stdin)!=NULL))
         {
            if (strlen(buffer) < BUFSIZE-1) break;
         }
         continue;                        /* go get next record if any    */
      }

      memset(tmp_buf, 0, sizeof(tmp_buf));
      strncpy(tmp_buf, buffer, sizeof(tmp_buf)-1);            /* save buffer in case of error */
      if(parse_record(buffer))            /* parse the record             */
      {
         if((log_rec.addr.s_addr = inet_addr(log_rec.hostname)) != INADDR_NONE)
         {
            DBT q, r;
            q.data = log_rec.hostname;
            q.size = strlen(log_rec.hostname);
		
            switch((dns_db->get)(dns_db, &q, &r, 0))
            {
               case -1: break;  /* Error while retrieving .. just ignore     */
               case 1:          /* No record on file, queue up for resolving */
               {
                  put_dnode(log_rec.hostname,
                            &log_rec.addr,
                            host_table);
                  break;
               }

               case 0: /* We have a record for this address */
               {
                  memcpy(&alignedRecord, r.data, sizeof(struct dnsRecord));
                  if((runtime - alignedRecord.timeStamp ) < DNS_CACHE_TTL)
                  {
                     if(!alignedRecord.numeric)  /* It is a name. Do nothing */
                        break;
                     /* otherise, it a number.. fall through */
                  }
                  else
                  {
                     /* queue up stale entry for retrieval */
                     put_dnode(log_rec.hostname,
                               &log_rec.addr,
                               host_table);
                     break;
                  }
               }
            }
         }
      }
   }
   verbose = save_verbose;     /* restore verbosity level... */

   listEntries = 0;
  
   /* build our linked list l_list  */
   for(i=0;i < MAXHASH; i++)
   {
      for(h_entries=host_table[i]; h_entries ; h_entries = h_entries->next)
      {
         h_entries->llist = l_list;
         l_list = h_entries;
         listEntries++;
      }
   }

   if(!l_list)
   {
      /* No valid addresses found... */
      if (verbose>1) printf("%s\n",msg_dns_none);
      tmp_flock.l_type=F_UNLCK;
      fcntl(dns_fd, F_SETLK, &tmp_flock);
      dns_db->close(dns_db);
      return 0;
   }

   /* process our list now... */
   process_list(l_list);

   /* display timing totals ? */
   end_time = times(&mytms);              /* display timing totals?   */
   if (time_me || (verbose>1))
   {
      if (verbose<2 && time_me) printf("DNS: ");
      printf("%lu %s ",listEntries, msg_addresses);

      /* get processing time (end-start) */
      temp_time = (float)(end_time-start_time)/CLK_TCK;
      printf("%s %.2f %s", msg_in, temp_time, msg_seconds);

      /* calculate records per second */
      if (temp_time)
         i=( (int)((float)listEntries/temp_time) );
      else i=0;

      if ( (i>0) && (i<=listEntries) ) printf(", %d/sec\n", i);
         else  printf("\n");
   }

   /* processing done, exit   */
   tmp_flock.l_type=F_UNLCK;
   fcntl(dns_fd, F_SETLK, &tmp_flock);
   dns_db->close(dns_db);
   return 0;

}

/*********************************************/
/* PROCESS_LIST - do the resoluton...        */
/*********************************************/

static void process_list(DNODEPTR l_list)
{
   DNODEPTR  trav;

   char   child_buf[MAXHOST+1] = {0};
   char   dns_buf[MAXHOST+1] = {0};
   int    i;
   int    pid;
   int    nof_children = 0;
   fd_set rd_set;
  
   struct sigaction sigChildAction;
  
   sigChildAction.sa_handler = sigChild;
   sigChildAction.sa_flags   = SA_NOCLDSTOP|SA_RESTART;
   sigemptyset(&sigChildAction.sa_mask);

   raiseSigChild = 0;
  
   sigaction(SIGCHLD, &sigChildAction, NULL);
  
   /* fire up our child processes */
   for(i=0; i < dns_children; i++)
   {
      if(pipe(child[i].inpipe))
      {
         if (verbose) fprintf(stderr,"INPIPE creation error");
         return;   /* exit(1) */
      }

      if(pipe(child[i].outpipe))
      {
         if (verbose) fprintf(stderr,"OUTPIPE creation error");
         return;   /* exit(1); */
      }

      /* fork it off */
      switch(pid=fork())
      {
         case -1:
         {
            if (verbose) fprintf(stderr,"FORK error");
            return;  /* exit(1); */
         }
	  
         case 0:             /* Child */
         {
            int size;

            struct hostent *res_ent;

            close(child[i].inpipe[0]);
            close(child[i].outpipe[1]);

            /* get struct in_addr here */
            while((size = read(child[i].outpipe[0], child_buf, MAXHOST)))
            {
               if(size < 0)
               {
                  perror("read error");
                  exit(1);
               }
               else
               {
                  if(debug_mode)
                  printf("Child got work: %lx(%d)\n",
                          *((unsigned long *)child_buf), size);

                  if((res_ent = gethostbyaddr(child_buf, size, AF_INET)))
                  {
                     /* must be at least 4 chars */
                     if (strlen(res_ent->h_name)>3)
                     {
                        if(debug_mode)
                           printf("Child got %s for %lx(%d), %d bytes\n",
                                   res_ent->h_name,
                                   *((unsigned long *)child_buf),
                                   size,strlen(res_ent->h_name));

                        /* If long hostname, take max domain name part */
                        if ((size = strlen(res_ent->h_name)) > MAXHOST)
                           strcpy(child_buf,(res_ent->h_name+(size-MAXHOST)));
                        else strcpy(child_buf, res_ent->h_name);
                        size = strlen(child_buf);
                     }
                     else
                     {
                        if (debug_mode)
                           printf("gethostbyaddr returned bad h_name!\n");
                     }
                  }
                  else
                  {
                     if(debug_mode)
                        printf("gethostbyaddr returned NULL! (%d)\n",h_errno);
                  }

                  if (write(child[i].inpipe[1], child_buf, size) == -1)
                  {
                     perror("write error");
                     exit(1);
                  }
               }
            }
            close(child[i].inpipe[1]);
            close(child[i].outpipe[0]);
		
            if(debug_mode)
               printf( "Child %d got closed input, shutting down\n", i);  

            fflush(stdout);
            exit(0);
         }  /* case 0 */
		
         default:
         {
            child[i].pid = pid;
            child[i].flags = DNS_CHILD_READY|DNS_CHILD_RUNNING;
            nof_children++;
            close(child[i].inpipe[1]);
            close(child[i].outpipe[0]);

            set_fl(child[i].inpipe[0], O_NONBLOCK);
         }
      }
   }

   trav = l_list;

   while(nof_children)
   {
      static struct timeval selectTimeval;
      int res;
      int max_fd;
	  
      FD_ZERO(&rd_set);
      max_fd = 0;

      if(raiseSigChild)
      {
         int pid;

         while((pid = waitpid(-1, NULL, WNOHANG)) > 0)
         {
            for(i=0;i<dns_children;i++)
            {
               if(child[i].pid == pid)
               {
                  child[i].pid = 0;
                  child[i].flags &= ~(DNS_CHILD_READY|DNS_CHILD_RUNNING);
                  nof_children--;

                  if(debug_mode)
                  printf("Reaped Child %d\n", pid);

                  break;
               }
            }
         }
         raiseSigChild--;
         continue; /* while, nof children has just changed */
      }

      for(i=0;i<dns_children;i++)
      {
         if(child[i].flags & DNS_CHILD_RUNNING) /* Child is running */
         {
            if(child[i].flags & DNS_CHILD_READY)
            {
               child[i].flags  &= ~DNS_CHILD_READY;

               if(trav)  /* something to resolve */
               {
                  if (write(child[i].outpipe[1], &(trav->addr.s_addr),
                     sizeof(trav->addr.s_addr)) != -1)
                  {
                     /* We will watch this child */
                     child[i].cur    = trav;
                     FD_SET(child[i].inpipe[0], &rd_set);
                     max_fd = MAX(max_fd, child[i].inpipe[0]);

                     if(debug_mode)
                        printf("Giving %s (%lx) to Child %d for resolving\n",
                                child[i].cur->string,
                                (unsigned long)child[i].cur->addr.s_addr, i);

                     trav = trav->llist;
                  }
                  else  /* write error */
                  {
                     if(errno != EINTR)           /* Could be a signal */
                     {
                        perror("Could not write to pipe");
                        close(child[i].outpipe[1]);           /* kill     */
                        child[i].flags &= ~DNS_CHILD_RUNNING; /* child    */
                     }
		  }
               }
               else /* List is complete */
               {
                  close(child[i].outpipe[1]);            /* Go away       */
                  child[i].flags &= ~DNS_CHILD_RUNNING;  /* Child is dead */
               }
            }
            else
            {
               /* Look, the busy child... */
               FD_SET(child[i].inpipe[0], &rd_set);
               max_fd = MAX(max_fd, child[i].inpipe[0]);
            }
         }
      }

      selectTimeval.tv_sec =  5; /* This stuff ticks in 5 second intervals */
      selectTimeval.tv_usec = 0;

      switch(res = select(max_fd+1, &rd_set, NULL, NULL, &selectTimeval))
      {
         case -1:
         {
            if(errno != EINTR)   /* Could be a signal */
            perror("Error in select");

            break;
         }

         case 0:   /* Timeout, just fall once through the child loop */
         {
            if(debug_mode)
            printf("tick\n");
		
            break;
         }

         default:
         {
            for(i=0; i< dns_children;i++)
            {
               if(!res)   /* All file descriptors done */
               break;

               if(FD_ISSET(child[i].inpipe[0], &rd_set))
               {
                  int size;

                  res--;  /* One less... */

                  if(debug_mode)
                  printf("Work requested from Child %d\n", i);

                  switch (size=read(child[i].inpipe[0], dns_buf, MAXHOST))
                  {
                     case -1:
                     {
                        if(errno != EINTR)
                        perror("Could not read from pipe");
                        break;
                     }
                     case 0:
                     {
                        /* EOF. Child has closed Pipe. It shouldn't have */
                        /*  done that, could be an error or something.   */
                        /*  Reap it                                      */
                        close(child[i].outpipe[1]);
                        child[i].flags &= ~DNS_CHILD_RUNNING;

                        if(debug_mode)
                           printf("Child %d wants to be reaped\n", i);

                        break;
                     }

                     default:
                     {
                        dns_buf[size] = '\0';
                        if(memcmp(dns_buf, &(child[i].cur->addr.s_addr),
                                    sizeof(child[i].cur->addr.s_addr)))
                        {
                           if(debug_mode)
                              printf("Got a result (%d): %s -> %s\n",
                                     i, child[i].cur->string, dns_buf);
                           db_put(child[i].cur->string, dns_buf, 0);
                        }
                        else
                        {
                           if(debug_mode)
                              printf("Could not resolve (%d):  %s\n",
                                     i, child[i].cur->string); 
                           /*
                           db_put(child[i].cur->string,child[i].cur->string,1);
                           */
                        }

                        if(debug_mode)
                           printf("Child %d back in task pool\n", i);

                        /* Child is back in the task pool */
                        child[i].flags |= DNS_CHILD_READY;
                        break;
                     }
                  }
               }
            }
            break;
         }
      }
   }
   return;
}

/*********************************************/
/* SET_FL - set flag on pipe FD              */
/*********************************************/

void set_fl(int fd, int flags)
{
   int val;

   /* get current flags */
   if ((val=fcntl(fd, F_GETFL, 0)) < 0)
      if (verbose) fprintf(stderr,"set_fl F_GETFL error\n");

   /* set them */
   val |= flags;

   /* and write them back */
   if ((val=fcntl(fd, F_SETFL, val)) < 0)
      if (verbose) fprintf(stderr,"set_fl F_SETFL error\n");
}

/*********************************************/
/* CLR_FL - clear flag on pipe FD            */
/*********************************************/

void clr_fl(int fd, int flags)
{
   int val;

   /* Get current flags */
   if ((val=fcntl(fd, F_GETFL, 0)) < 0)
      if (verbose) fprintf(stderr,"clr_fl F_GETFL error\n");

   /* set them */
   val &= ~flags;

   /* and write them back */
   if ((val=fcntl(fd, F_SETFL, val)) < 0)
      if (verbose) fprintf(stderr,"clr_fl F_SETFL error\n");
}

/*********************************************/
/* DB_PUT - put key/val in the cache db      */
/*********************************************/

static void db_put(char *key, char *value, int numeric)
{
   DBT k, v;
   struct dnsRecord *recPtr = NULL;
   int nameLen = strlen(value)+1;
   /* Align to multiple of eight bytes */
   int recSize = (sizeof(struct dnsRecord)+nameLen+7) & ~0x7;
	
   /* make sure we have a db ;) */
   if(dns_db)
   {
      if((recPtr = calloc(1, recSize)))
      {
         recPtr->timeStamp = runtime;
         recPtr->numeric = numeric;
         memcpy(&recPtr->hostName, value, nameLen);

         k.data = key;
         k.size = strlen(key);

         v.size = recSize;
         v.data = recPtr;
	  
         if((dns_db->put)(dns_db, &k, &v, 0) < 0)
            if (verbose>1) fprintf(stderr,"db_put fail!\n");
         free(recPtr);
      }
   }
}

/*********************************************/
/* SIGCHILD - raise our signal               */
/*********************************************/

static void sigChild(int signum)
{
   raiseSigChild++;
}

/*********************************************/
/* OPEN_CACHE - open our cache file RDONLY   */
/*********************************************/

int open_cache()
{
   struct stat  dbStat;
   struct flock tmp_flock;

   tmp_flock.l_whence=SEEK_SET;    /* default flock fields */
   tmp_flock.l_start=0;
   tmp_flock.l_len=0;
   tmp_flock.l_pid=0;
   tmp_flock.l_type=F_RDLCK;

   /* double check filename was specified */
   if(!dns_cache) { dns_db=NULL; return 0; }

   /* minimal sanity check on it */
   if(stat(dns_cache, &dbStat) < 0)
   {
      if(errno != ENOENT) return 0;
   }
   else
   {
      if(!dbStat.st_size)  /* bogus file, probably from a crash */
      {
         unlink(dns_cache);  /* remove it so we can recreate... */
      }
   }
  
   /* open cache file */
   if(!(dns_db = dbopen(dns_cache, O_RDONLY, 0664, DB_HASH, NULL)))
   {
      /* Error: Unable to open DNS cache file <filename> */
      if (verbose) fprintf(stderr,"%s %s\n",msg_dns_nodb,dns_cache);
      return 0;                  /* disable cache */
   }

   /* get file descriptor */
   dns_fd = dns_db->fd(dns_db);

   /* Get shared lock on cache file */
   if (fcntl(dns_fd, F_SETLK, &tmp_flock) < 0)
   {
      if (verbose) fprintf(stderr,"%s %s\n",msg_dns_nolk,dns_cache);
      dns_db->close(dns_db);
      return 0;
   }
   return 1;
}

/*********************************************/
/* CLOSE_CACHE - close our RDONLY cache      */
/*********************************************/

int close_cache()
{
   struct flock tmp_flock;

   tmp_flock.l_whence=SEEK_SET;    /* default flock fields */
   tmp_flock.l_start=0;
   tmp_flock.l_len=0;
   tmp_flock.l_pid=0;
   tmp_flock.l_type=F_UNLCK;

   /* clear lock and close cache file */
   fcntl(dns_fd, F_SETLK, &tmp_flock);
   dns_db->close(dns_db);
   return 1;
}

#endif  /* USE_DNS */
