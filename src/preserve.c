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

#include "webalizer.h"                        /* main header              */
#include "lang.h"
#include "hashtab.h"
#include "parser.h"
#include "preserve.h"

/* local variables */
int     hist_month[12], hist_year[12];        /* arrays for monthly total */
u_long  hist_hit[12];                         /* calculations: used to    */
u_long  hist_files[12];                       /* produce index.html       */
u_long  hist_site[12];                        /* these are read and saved */
double  hist_xfer[12];                        /* in the history file      */
u_long  hist_page[12];
u_long  hist_visit[12];

int     hist_fday[12], hist_lday[12];         /* first/last day arrays    */

/*********************************************/
/* GET_HISTORY - load in history file        */
/*********************************************/

void get_history()
{
   int i,numfields;
   FILE *hist_fp;
   char buffer[BUFSIZE];

   /* first initalize internal array */
   for (i=0;i<12;i++)
   {
      hist_month[i]=hist_year[i]=hist_fday[i]=hist_lday[i]=0;
      hist_hit[i]=hist_files[i]=hist_site[i]=hist_page[i]=hist_visit[i]=0;
      hist_xfer[i]=0.0;
   }

   hist_fp=fopen(hist_fname,"r");

   if (hist_fp)
   {
      if (verbose>1) printf("%s %s\n",msg_get_hist,hist_fname);
      while ((fgets(buffer,BUFSIZE,hist_fp)) != NULL)
      {
         i = atoi(buffer) -1;
         if (i>11)
         {
            if (verbose)
               fprintf(stderr,"%s (mth=%d)\n",msg_bad_hist,i+1);
            continue;
         }

         /* month# year# requests files sites xfer firstday lastday */
         numfields = sscanf(buffer,"%d %d %lu %lu %lu %lf %d %d %lu %lu",
                       &hist_month[i],
                       &hist_year[i],
                       &hist_hit[i],
                       &hist_files[i],
                       &hist_site[i],
                       &hist_xfer[i],
                       &hist_fday[i],
                       &hist_lday[i],
                       &hist_page[i],
                       &hist_visit[i]);

         if (numfields==8)     /* kludge for reading 1.20.xx history files */
         {
            hist_page[i] = 0;
            hist_visit[i] = 0;
         }
      }
      fclose(hist_fp);
   }
   else if (verbose>1) printf("%s\n",msg_no_hist);
}

/*********************************************/
/* PUT_HISTORY - write out history file      */
/*********************************************/

void put_history()
{
   int i;
   FILE *hist_fp;

   hist_fp = fopen(hist_fname,"w");

   if (hist_fp)
   {
      if (verbose>1) printf("%s\n",msg_put_hist);
      for (i=0;i<12;i++)
      {
         if ((hist_month[i] != 0) && (hist_hit[i] != 0))
         {
            fprintf(hist_fp,"%d %d %lu %lu %lu %.0f %d %d %lu %lu\n",
                            hist_month[i],
                            hist_year[i],
                            hist_hit[i],
                            hist_files[i],
                            hist_site[i],
                            hist_xfer[i],
                            hist_fday[i],
                            hist_lday[i],
                            hist_page[i],
                            hist_visit[i]);
         }
      }
      fclose(hist_fp);
   }
   else
      if (verbose)
      fprintf(stderr,"%s %s\n",msg_hist_err,hist_fname);
}

/*********************************************/
/* SAVE_STATE - save internal data structs   */
/*********************************************/

int save_state()
{
   HNODEPTR hptr;
   UNODEPTR uptr;
   RNODEPTR rptr;
   ANODEPTR aptr;
   SNODEPTR sptr;
   INODEPTR iptr;

   FILE *fp;
   int  i;

   char buffer[BUFSIZE];

   /* Open data file for write */
   fp=fopen(state_fname,"w");
   if (fp==NULL) return 1;

   /* Saving current run data... */
   if (verbose>1)
   {
      sprintf(buffer,"%02d/%02d/%04d %02d:%02d:%02d",
       cur_month,cur_day,cur_year,cur_hour,cur_min,cur_sec);
      printf("%s [%s]\n",msg_put_data,buffer);
   }

   /* first, save the easy stuff */
   /* Header record */
   snprintf(buffer, sizeof(buffer),
     "# Webalizer V%s-%s Incremental Data - %02d/%02d/%04d %02d:%02d:%02d\n",
      version,editlvl,cur_month,cur_day,cur_year,cur_hour,cur_min,cur_sec);
   if (fputs(buffer,fp)==EOF) return 1;  /* error exit */

   /* Current date/time          */
   sprintf(buffer,"%d %d %d %d %d %d\n",
        cur_year, cur_month, cur_day, cur_hour, cur_min, cur_sec);
   if (fputs(buffer,fp)==EOF) return 1;  /* error exit */

   /* Monthly totals for sites, urls, etc... */
   sprintf(buffer,"%lu %lu %lu %lu %lu %lu %.0f %lu %lu %lu\n",
        t_hit, t_file, t_site, t_url,
        t_ref, t_agent, t_xfer, t_page, t_visit, t_user);
   if (fputs(buffer,fp)==EOF) return 1;  /* error exit */

   /* Daily totals for sites, urls, etc... */
   sprintf(buffer,"%lu %lu %lu %d %d\n",
        dt_site, ht_hit, mh_hit, f_day, l_day);
   if (fputs(buffer,fp)==EOF) return 1;  /* error exit */

   /* Monthly (by day) total array */
   for (i=0;i<31;i++)
   {
      sprintf(buffer,"%lu %lu %.0f %lu %lu %lu\n",
        tm_hit[i],tm_file[i],tm_xfer[i],tm_site[i],tm_page[i],tm_visit[i]);
      if (fputs(buffer,fp)==EOF) return 1;  /* error exit */
   }

   /* Daily (by hour) total array */
   for (i=0;i<24;i++)
   {
      sprintf(buffer,"%lu %lu %.0f %lu\n",
        th_hit[i],th_file[i],th_xfer[i],th_page[i]);
      if (fputs(buffer,fp)==EOF) return 1;  /* error exit */
   }

   /* Response codes */
   for (i=0;i<TOTAL_RC;i++)
   {
      sprintf(buffer,"%lu\n",response[i].count);
      if (fputs(buffer,fp)==EOF) return 1;  /* error exit */
   }

   /* now we need to save our linked lists */
   /* URL list */
   if (fputs("# -urls- \n",fp)==EOF) return 1;  /* error exit */
   for (i=0;i<MAXHASH;i++)
   {
      uptr=um_htab[i];
      while (uptr!=NULL)
      {
         sprintf(buffer,"%s\n%d %lu %lu %.0f %lu %lu\n", uptr->string,
              uptr->flag, uptr->count, uptr->files, uptr->xfer,
              uptr->entry, uptr->exit);
         if (fputs(buffer,fp)==EOF) return 1;
         uptr=uptr->next;
      }
   }
   if (fputs("# End Of Table - urls\n",fp)==EOF) return 1;  /* error exit */

   /* daily hostname list */
   if (fputs("# -sites- (monthly)\n",fp)==EOF) return 1;  /* error exit */

   for (i=0;i<MAXHASH;i++)
   {
      hptr=sm_htab[i];
      while (hptr!=NULL)
      {
         sprintf(buffer,"%s\n%d %lu %lu %.0f %lu %lu\n%s\n",
              hptr->string,
              hptr->flag,
              hptr->count,
              hptr->files,
              hptr->xfer,
              hptr->visit,
              hptr->tstamp,
              (hptr->lasturl==blank_str)?"-":hptr->lasturl);
         if (fputs(buffer,fp)==EOF) return 1;  /* error exit */
         hptr=hptr->next;
      }
   }
   if (fputs("# End Of Table - sites (monthly)\n",fp)==EOF) return 1;

   /* hourly hostname list */
   if (fputs("# -sites- (daily)\n",fp)==EOF) return 1;  /* error exit */
   for (i=0;i<MAXHASH;i++)
   {
      hptr=sd_htab[i];
      while (hptr!=NULL)
      {
         sprintf(buffer,"%s\n%d %lu %lu %.0f %lu %lu\n%s\n",
              hptr->string,
              hptr->flag,
              hptr->count,
              hptr->files,
              hptr->xfer,
              hptr->visit,
              hptr->tstamp,
              (hptr->lasturl==blank_str)?"-":hptr->lasturl);
         if (fputs(buffer,fp)==EOF) return 1;
         hptr=hptr->next;
      }
   }
   if (fputs("# End Of Table - sites (daily)\n",fp)==EOF) return 1;

   /* Referrer list */
   if (fputs("# -referrers- \n",fp)==EOF) return 1;  /* error exit */
   if (t_ref != 0)
   {
      for (i=0;i<MAXHASH;i++)
      {
         rptr=rm_htab[i];
         while (rptr!=NULL)
         {
            sprintf(buffer,"%s\n%d %lu\n", rptr->string,
                 rptr->flag, rptr->count);
            if (fputs(buffer,fp)==EOF) return 1;  /* error exit */
            rptr=rptr->next;
         }
      }
   }
   if (fputs("# End Of Table - referrers\n",fp)==EOF) return 1;

   /* User agent list */
   if (fputs("# -agents- \n",fp)==EOF) return 1;  /* error exit */
   if (t_agent != 0)
   {
      for (i=0;i<MAXHASH;i++)
      {
         aptr=am_htab[i];
         while (aptr!=NULL)
         {
            sprintf(buffer,"%s\n%d %lu\n", aptr->string,
                 aptr->flag, aptr->count);
            if (fputs(buffer,fp)==EOF) return 1;  /* error exit */
            aptr=aptr->next;
         }
      }
   }
   if (fputs("# End Of Table - agents\n",fp)==EOF) return 1;

   /* Search String list */
   if (fputs("# -search strings- \n",fp)==EOF) return 1;  /* error exit */
   for (i=0;i<MAXHASH;i++)
   {
      sptr=sr_htab[i];
      while (sptr!=NULL)
      {
         sprintf(buffer,"%s\n%lu\n", sptr->string,sptr->count);
         if (fputs(buffer,fp)==EOF) return 1;  /* error exit */
         sptr=sptr->next;
      }
   }
   if (fputs("# End Of Table - search strings\n",fp)==EOF) return 1;

   /* username list */
   if (fputs("# -usernames- \n",fp)==EOF) return 1;  /* error exit */

   for (i=0;i<MAXHASH;i++)
   {
      iptr=im_htab[i];
      while (iptr!=NULL)
      {
         sprintf(buffer,"%s\n%d %lu %lu %.0f %lu %lu\n",
              iptr->string,
              iptr->flag,
              iptr->count,
              iptr->files,
              iptr->xfer,
              iptr->visit,
              iptr->tstamp);
         if (fputs(buffer,fp)==EOF) return 1;  /* error exit */
         iptr=iptr->next;
      }
   }
   if (fputs("# End Of Table - usernames\n",fp)==EOF) return 1;

   fclose(fp);          /* close data file...                            */
   return 0;            /* successful, return with good return code      */
}

/*********************************************/
/* RESTORE_STATE - reload internal run data  */
/*********************************************/

int restore_state()
{
   FILE *fp;
   int  i;
   struct hnode t_hnode;         /* Temporary hash nodes */
   struct unode t_unode;
   struct rnode t_rnode;
   struct anode t_anode;
   struct snode t_snode;
   struct inode t_inode;

   char   buffer[BUFSIZE];
   char   tmp_buf[BUFSIZE];

   u_long ul_bogus=0;

   fp=fopen(state_fname,"r");
   if (fp==NULL)
   {
      /* Previous run data not found... */
      if (verbose>1) printf("%s\n",msg_no_data);
      return 0;   /* return with ok code */
   }

   /* Reading previous run data... */
   if (verbose>1) printf("%s %s\n",msg_get_data,state_fname);

   /* get easy stuff */
   sprintf(tmp_buf,"# Webalizer V%s    ",version);
   if ((fgets(buffer,BUFSIZE,fp)) != NULL)                 /* Header record */
     {if (strncmp(buffer,tmp_buf,17)) return 99;} /* bad magic? */
   else return 1;   /* error exit */

   /* Get current timestamp */
   if ((fgets(buffer,BUFSIZE,fp)) != NULL)
   {
      sscanf(buffer,"%d %d %d %d %d %d",
       &cur_year, &cur_month, &cur_day,
       &cur_hour, &cur_min, &cur_sec);
   } else return 2;  /* error exit */

   /* calculate current timestamp (seconds since epoch) */
   cur_tstamp=((jdate(cur_day,cur_month,cur_year)-epoch)*86400)+
                     (cur_hour*3600)+(cur_min*60)+cur_sec;

   /* Get monthly totals */
   if ((fgets(buffer,BUFSIZE,fp)) != NULL)
   {
      sscanf(buffer,"%lu %lu %lu %lu %lu %lu %lf %lu %lu %lu",
       &t_hit, &t_file, &t_site, &t_url,
       &t_ref, &t_agent, &t_xfer, &t_page, &t_visit, &t_user);
   } else return 3;  /* error exit */
     
   /* Get daily totals */
   if ((fgets(buffer,BUFSIZE,fp)) != NULL)
   {
      sscanf(buffer,"%lu %lu %lu %d %d",
       &dt_site, &ht_hit, &mh_hit, &f_day, &l_day);
   } else return 4;  /* error exit */

   /* get daily totals */
   for (i=0;i<31;i++)
   {
      if ((fgets(buffer,BUFSIZE,fp)) != NULL)
      {
         sscanf(buffer,"%lu %lu %lf %lu %lu %lu",
          &tm_hit[i],&tm_file[i],&tm_xfer[i],&tm_site[i],&tm_page[i],
          &tm_visit[i]);
      } else return 5;  /* error exit */
   }

   /* get hourly totals */
   for (i=0;i<24;i++)
   {
      if ((fgets(buffer,BUFSIZE,fp)) != NULL)
      {
         sscanf(buffer,"%lu %lu %lf %lu",
          &th_hit[i],&th_file[i],&th_xfer[i],&th_page[i]);
      } else return 6;  /* error exit */
   }

   /* get response code totals */
   for (i=0;i<TOTAL_RC;i++)
   {
      if ((fgets(buffer,BUFSIZE,fp)) != NULL)
         sscanf(buffer,"%lu",&response[i].count);
      else return 7;  /* error exit */
   }

   /* Kludge for V2.01-06 TOTAL_RC off by one bug */
   if (!strncmp(buffer,"# -urls- ",9)) response[TOTAL_RC-1].count=0;
   else
   {
      /* now do hash tables */

      /* url table */
      if ((fgets(buffer,BUFSIZE,fp)) != NULL)            /* Table header */
      { if (strncmp(buffer,"# -urls- ",9)) return 10; }  /* (url)        */
      else return 10;   /* error exit */
   }

   while ((fgets(buffer,BUFSIZE,fp)) != NULL)
   {
      if (!strncmp(buffer,"# End Of Table ",15)) break;
      strncpy(tmp_buf,buffer,MAXURLH);
      tmp_buf[strlen(tmp_buf)-1]=0;

      if ((fgets(buffer,BUFSIZE,fp)) == NULL) return 10;  /* error exit */
      if (!isdigit((int)buffer[0])) return 10;  /* error exit */

      /* load temporary node data */
      sscanf(buffer,"%d %lu %lu %lf %lu %lu",
         &t_unode.flag,&t_unode.count,
         &t_unode.files, &t_unode.xfer,
         &t_unode.entry, &t_unode.exit);

      /* Good record, insert into hash table */
      if (put_unode(tmp_buf,t_unode.flag,t_unode.count,
         t_unode.xfer,&ul_bogus,t_unode.entry,t_unode.exit,um_htab))
      {
         if (verbose)
         /* Error adding URL node, skipping ... */
         fprintf(stderr,"%s %s\n", msg_nomem_u, t_unode.string);
      }
   }

   /* monthly sites table */
   if ((fgets(buffer,BUFSIZE,fp)) != NULL)               /* Table header */
   { if (strncmp(buffer,"# -sites- ",10)) return 8; }    /* (monthly)    */
   else return 8;   /* error exit */

   while ((fgets(buffer,BUFSIZE,fp)) != NULL)
   {
      /* Check for end of table */
      if (!strncmp(buffer,"# End Of Table ",15)) break;
      strncpy(tmp_buf,buffer,MAXHOST);
      tmp_buf[strlen(buffer)-1]=0;

      if ((fgets(buffer,BUFSIZE,fp)) == NULL) return 8;  /* error exit */
      if (!isdigit((int)buffer[0])) return 8;  /* error exit */

      /* load temporary node data */
      sscanf(buffer,"%d %lu %lu %lf %lu %lu",
         &t_hnode.flag,&t_hnode.count,
         &t_hnode.files, &t_hnode.xfer,
         &t_hnode.visit, &t_hnode.tstamp);

      /* get last url */
      if ((fgets(buffer,BUFSIZE,fp)) == NULL) return 8;  /* error exit */
      if (buffer[0]=='-') t_hnode.lasturl=blank_str;
      else
      {
         buffer[strlen(buffer)-1]=0;
         t_hnode.lasturl=find_url(buffer);
      }

      /* Good record, insert into hash table */
      if (put_hnode(tmp_buf,t_hnode.flag,
         t_hnode.count,t_hnode.files,t_hnode.xfer,&ul_bogus,
         t_hnode.visit+1,t_hnode.tstamp,t_hnode.lasturl,sm_htab))
      {
         /* Error adding host node (monthly), skipping .... */
         if (verbose) fprintf(stderr,"%s %s\n",msg_nomem_mh, t_hnode.string);
      }
   }

   /* Daily sites table */
   if ((fgets(buffer,BUFSIZE,fp)) != NULL)               /* Table header */
   { if (strncmp(buffer,"# -sites- ",10)) return 9; }    /* (daily)      */
   else return 9;   /* error exit */

   while ((fgets(buffer,BUFSIZE,fp)) != NULL)
   {
      /* Check for end of table */
      if (!strncmp(buffer,"# End Of Table ",15)) break;
      strncpy(tmp_buf,buffer,MAXHOST);
      tmp_buf[strlen(buffer)-1]=0;

      if ((fgets(buffer,BUFSIZE,fp)) == NULL) return 9;  /* error exit */
      if (!isdigit((int)buffer[0])) return 9;  /* error exit */

      /* load temporary node data */
      sscanf(buffer,"%d %lu %lu %lf %lu %lu",
          &t_hnode.flag,&t_hnode.count,
          &t_hnode.files, &t_hnode.xfer,
          &t_hnode.visit, &t_hnode.tstamp);

      /* get last url */
      if ((fgets(buffer,BUFSIZE,fp)) == NULL) return 9;  /* error exit */
      if (buffer[0]=='-') t_hnode.lasturl=blank_str;
      else
      {
         buffer[strlen(buffer)-1]=0;
         t_hnode.lasturl=find_url(buffer);
      }

      /* Good record, insert into hash table */
      if (put_hnode(tmp_buf,t_hnode.flag,
         t_hnode.count,t_hnode.files,t_hnode.xfer,&ul_bogus,
         t_hnode.visit+1,t_hnode.tstamp,t_hnode.lasturl,sd_htab))
      {
         /* Error adding host node (daily), skipping .... */
         if (verbose) fprintf(stderr,"%s %s\n",msg_nomem_dh, t_hnode.string);
      }
   }

   /* Referrers table */
   if ((fgets(buffer,BUFSIZE,fp)) != NULL)               /* Table header */
   { if (strncmp(buffer,"# -referrers- ",14)) return 11; } /* (referrers)*/
   else return 11;   /* error exit */

   while ((fgets(buffer,BUFSIZE,fp)) != NULL)
   {
      if (!strncmp(buffer,"# End Of Table ",15)) break;
      strncpy(tmp_buf,buffer,MAXREFH);
      tmp_buf[strlen(buffer)-1]=0;

      if ((fgets(buffer,BUFSIZE,fp)) == NULL) return 11;  /* error exit */
      if (!isdigit((int)buffer[0])) return 11;  /* error exit */

      /* load temporary node data */
      sscanf(buffer,"%d %lu",&t_rnode.flag,&t_rnode.count);

      /* insert node */
      if (put_rnode(tmp_buf,t_rnode.flag,
         t_rnode.count, &ul_bogus, rm_htab))
      {
         if (verbose) fprintf(stderr,"%s %s\n", msg_nomem_r, log_rec.refer);
      }
   }

   /* Agents table */
   if ((fgets(buffer,BUFSIZE,fp)) != NULL)               /* Table header */
   { if (strncmp(buffer,"# -agents- ",11)) return 12; } /* (agents)*/
   else return 12;   /* error exit */

   while ((fgets(buffer,BUFSIZE,fp)) != NULL)
   {
      if (!strncmp(buffer,"# End Of Table ",15)) break;
      strncpy(tmp_buf,buffer,MAXAGENT);
      tmp_buf[strlen(buffer)-1]=0;

      if ((fgets(buffer,BUFSIZE,fp)) == NULL) return 12;  /* error exit */
      if (!isdigit((int)buffer[0])) return 12;  /* error exit */

      /* load temporary node data */
      sscanf(buffer,"%d %lu",&t_anode.flag,&t_anode.count);

      /* insert node */
      if (put_anode(tmp_buf,t_anode.flag,t_anode.count,
         &ul_bogus,am_htab))
      {
         if (verbose) fprintf(stderr,"%s %s\n", msg_nomem_a, log_rec.agent);
      }
   }

   /* Search Strings table */
   if ((fgets(buffer,BUFSIZE,fp)) != NULL)               /* Table header */
   { if (strncmp(buffer,"# -search string",16)) return 13; }  /* (search)*/
   else return 13;   /* error exit */

   while ((fgets(buffer,BUFSIZE,fp)) != NULL)
   {
      if (!strncmp(buffer,"# End Of Table ",15)) break;
      strncpy(tmp_buf,buffer,MAXSRCH);
      tmp_buf[strlen(buffer)-1]=0;

      if ((fgets(buffer,BUFSIZE,fp)) == NULL) return 13;  /* error exit */
      if (!isdigit((int)buffer[0])) return 13;  /* error exit */

      /* load temporary node data */
      sscanf(buffer,"%lu",&t_snode.count);

      /* insert node */
      if (put_snode(tmp_buf,t_snode.count,sr_htab))
      {
         if (verbose) fprintf(stderr,"%s %s\n", msg_nomem_sc, t_snode.string);
      }
   }

   /* usernames table */
   if ((fgets(buffer,BUFSIZE,fp)) != NULL)               /* Table header */
   { if (strncmp(buffer,"# -usernames- ",10)) return 14; }
   else return 14;   /* error exit */

   while ((fgets(buffer,BUFSIZE,fp)) != NULL)
   {
      /* Check for end of table */
      if (!strncmp(buffer,"# End Of Table ",15)) break;
      strncpy(tmp_buf,buffer,MAXIDENT);
      tmp_buf[strlen(buffer)-1]=0;

      if ((fgets(buffer,BUFSIZE,fp)) == NULL) return 14;  /* error exit */
      if (!isdigit((int)buffer[0])) return 14;  /* error exit */

      /* load temporary node data */
      sscanf(buffer,"%d %lu %lu %lf %lu %lu",
         &t_inode.flag,&t_inode.count,
         &t_inode.files, &t_inode.xfer,
         &t_inode.visit, &t_inode.tstamp);

      /* Good record, insert into hash table */
      if (put_inode(tmp_buf,t_inode.flag,
         t_inode.count,t_inode.files,t_inode.xfer,&ul_bogus,
         t_inode.visit+1,t_inode.tstamp,im_htab))
      {
         if (verbose)
         /* Error adding username node, skipping .... */
         fprintf(stderr,"%s %s\n",msg_nomem_i, t_inode.string);
      }
   }

   fclose(fp);
   check_dup = 1;              /* enable duplicate checking */
   return 0;                   /* return with ok code       */
}
