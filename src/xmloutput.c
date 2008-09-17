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
#include "preserve.h"
#include "linklist.h"
#include "xmloutput.h"

/* internal function prototypes */
void	write_xml_head(char *, FILE *);				/* head of xml document */
void  write_xml_tail(FILE *);       /* foot of xml document */
//void    month_links();                              /* Page links          */
void    month_total_table();                        /* monthly total table */
void    daily_total_table();                        /* daily total table   */
void    hourly_total_fragment();                       /* hourly total table  */
void    top_sites_fragment(int);                       /* top n sites table   */
void    top_urls_fragment(int);                        /* top n URL's table   */
void    top_entry_fragment(int);                       /* top n entry/exits   */
void    top_refs_fragment();                           /* top n referrers ""  */
void    top_agents_fragment();                         /* top n u-agents  ""  */
void    top_ctry_fragment();                           /* top n countries ""  */
void    top_search_fragment();                         /* top n search strs   */
void    top_users_fragment();                          /* top n ident table   */
u_long  load_url_array(  UNODEPTR *);               /* load URL array      */
u_long  load_site_array( HNODEPTR *);               /* load Site array     */
u_long  load_ref_array(  RNODEPTR *);               /* load Refs array     */
u_long  load_agent_array(ANODEPTR *);               /* load Agents array   */
u_long  load_srch_array( SNODEPTR *);               /* load srch str array */
u_long  load_ident_array(INODEPTR *);               /* load ident array    */
int	qs_url_cmph( const void*, const void*);     /* compare by hits     */
int	qs_url_cmpk( const void*, const void*);     /* compare by kbytes   */
int	qs_url_cmpn( const void*, const void*);     /* compare by entrys   */
int	qs_url_cmpx( const void*, const void*);     /* compare by exits    */
int	qs_site_cmph(const void*, const void*);     /* compare by hits     */
int	qs_site_cmpk(const void*, const void*);     /* compare by kbytes   */
int	qs_ref_cmph( const void*, const void*);     /* compare by hits     */
int     qs_agnt_cmph(const void*, const void*);     /* compare by hits     */
int     qs_srch_cmph(const void*, const void*);     /* compare by hits     */
int     qs_ident_cmph(const void*, const void*);    /* compare by hits     */
int     qs_ident_cmpk(const void*, const void*);    /* compare by kbytes   */

int     all_sites_page(u_long, u_long);             /* output site page    */
int     all_urls_page(u_long, u_long);              /* output urls page    */
int     all_refs_page(u_long, u_long);              /* output refs page    */
int     all_agents_page(u_long, u_long);            /* output agents page  */
int     all_search_page(u_long, u_long);            /* output search page  */
int     all_users_page(u_long, u_long);             /* output ident page   */
void    dump_all_sites();                           /* dump sites tab file */
void    dump_all_urls();                            /* dump urls tab file  */
void    dump_all_refs();                            /* dump refs tab file  */
void    dump_all_agents();                          /* dump agents file    */
void    dump_all_users();                           /* dump usernames file */
void    dump_all_search();                          /* dump search file    */

/* define some colors for HTML */
#define WHITE          "#FFFFFF"
#define BLACK          "#000000"
#define RED            "#FF0000"
#define ORANGE         "#FF8000"
#define LTBLUE         "#0080FF"
#define BLUE           "#0000FF"
#define GREEN          "#00FF00"
#define DKGREEN        "#008040"
#define GREY           "#C0C0C0"
#define LTGREY         "#E8E8E8"
#define YELLOW         "#FFFF00"
#define PURPLE         "#FF00FF"
#define CYAN           "#00E0FF"
#define GRPCOLOR       "#D0D0E0"

/* sort arrays */
UNODEPTR *u_array      = NULL;                /* Sort array for URL's     */
HNODEPTR *h_array      = NULL;                /* hostnames (sites)        */
RNODEPTR *r_array      = NULL;                /* referrers                */
ANODEPTR *a_array      = NULL;                /* user agents              */
SNODEPTR *s_array      = NULL;                /* search strings           */
INODEPTR *i_array      = NULL;                /* ident strings (username) */
u_long   a_ctr         = 0;                   /* counter for sort array   */

FILE     *out_fp;
FILE	 *xml_fp;


/* DANNYS NEW XMLOUTPUT FUNCTIONS */
void month_total_fragment()
{
   int i,days_in_month;
   u_long max_files=0,max_hits=0,max_visits=0,max_pages=0;
   double max_xfer=0.0;

   days_in_month=(l_day-f_day)+1;
   for (i=0;i<31;i++)
   {  /* Get max/day values */
      if (tm_hit[i]>max_hits)     max_hits  = tm_hit[i];
      if (tm_file[i]>max_files)   max_files = tm_file[i];
      if (tm_page[i]>max_pages)   max_pages = tm_page[i];
      if (tm_visit[i]>max_visits) max_visits= tm_visit[i];
      if (tm_xfer[i]>max_xfer)    max_xfer  = tm_xfer[i];
   }
	fprintf(xml_fp,"\t\t<totals hits=\"%lu\" files=\"%lu\" pages=\"%lu\" visits=\"%lu\" transfered=\"%.0f\" uniq_sites=\"%lu\" uniq_urls=\"%lu\" uniq_usernames=\"%lu\" />\n",
		t_hit, t_file, t_page, t_visit, t_xfer/1024, t_site, t_url, t_user);
	fprintf(xml_fp, "\t\t<timed>\n");
	fprintf(xml_fp, "\t\t\t<hourly hits_avg=\"%lu\" hits_max=\"%lu\" />\n", t_hit/(24*days_in_month), mh_hit);
	fprintf(xml_fp, "\t\t\t<daily hits_avg=\"%lu\" hits_max=\"%lu\" files_avg=\"%lu\" files_max=\"%lu\" pages_avg=\"%lu\" pages_max=\"%lu\" visits_avg=\"%lu\" visits_max=\"%lu\" transfered_avg=\"%.0f\" transfered_max=\"%.0f\" />\n",
		t_hit/(24*days_in_month), mh_hit,
		t_hit/days_in_month, max_hits,
		t_file/days_in_month, max_files,
		t_page/days_in_month, max_pages,
		t_visit/days_in_month, max_visits,
		(t_xfer/1024)/days_in_month, max_xfer/1024);
	fprintf(xml_fp, "\t\t</timed>\n");
	fprintf(xml_fp, "\t\t<responsecodes>\n");
   // /**********************************************/
   // /* response code totals */
   for (i=0;i<TOTAL_RC;i++)
   {
      if (response[i].count != 0)
		 fprintf(xml_fp, "");
   //      fprintf(xml_fp,"<TR><TD><FONT SIZE=\"-1\">%s</FONT></TD>\n"         \
   //         "<TD ALIGN=right COLSPAN=2><FONT SIZE=\"-1\"><B>%lu</B>"         \
   //         "</FONT></TD></TR>\n",
      fprintf(xml_fp, "\t\t\t<responsecode id=\"%d\" desc=\"%s\" count=\"%lu\" />\n",
            response[i].resp_code, response[i].desc, response[i].count);
   }
	fprintf(xml_fp, "\t\t</responsecodes>\n");
}
int daily_total_fragment() {
	int i;

   /* Daily stats */
	fprintf(xml_fp,"\t\t<daily>\n");
	// fprintf(xml_fp,"\t\t\t<!-- Note that the transfered-values are in KiloBytes (/1024) -->\n");
   /* skip beginning blank days in a month */
   for (i=0;i<hist_lday[cur_month-1];i++) if (tm_hit[i]!=0) break;
   if (i==hist_lday[cur_month-1]) i=0;

   for (;i<hist_lday[cur_month-1];i++)
   {
	fprintf(xml_fp,"\t\t\t<day id=\"%d\" hits=\"%lu\" hits_percent=\"%3.02f%%\" files=\"%lu\" files_percent=\"%3.02f%%\" pages=\"%lu\" pages_percent=\"%3.02f%%\" visits=\"%lu\" visits_percent=\"%3.02f%%\" sites=\"%lu\" sites_percent=\"%3.02f%%\" transfered=\"%.0f\" transfered_percent=\"%3.02f%%\" />\n", i+1, 
		tm_hit[i], PCENT(tm_hit[i],t_hit), 
		tm_file[i], PCENT(tm_file[i],t_file),
		tm_page[i],PCENT(tm_page[i],t_page),
		tm_visit[i],PCENT(tm_visit[i],t_visit),
		tm_site[i],PCENT(tm_site[i],t_site),
		tm_xfer[i]/1024,PCENT(tm_xfer[i],t_xfer));
   }
	fprintf(xml_fp,"\t\t</daily>\n");
	
	return(1);
}
int write_month_xml()
{
   int i;
   char xml_fname[256];           /* filename storage areas...       */

   char buffer[BUFSIZE];           /* scratch buffer                  */
   char dtitle[256];
   char htitle[256];

   if (verbose>1)
      printf("%s %s %d\n",msg_gen_rpt, l_month[cur_month-1], cur_year); 

   /* update history */
   i=cur_month-1;
   hist_month[i] =  cur_month;
   hist_year[i]  =  cur_year;
   hist_hit[i]   =  t_hit;
   hist_files[i] =  t_file;
   hist_page[i]  =  t_page;
   hist_visit[i] =  t_visit;
   hist_site[i]  =  t_site;
   hist_xfer[i]  =  t_xfer/1024;
   hist_fday[i]  =  f_day;
   hist_lday[i]  =  l_day;

   /* fill in filenames */
   snprintf(xml_fname, sizeof(xml_fname),"%04d%02d.xml",cur_year,cur_month);

   /* now do xml stuff... */
   /* first, open the file */
   if ( (xml_fp=open_out_file(xml_fname))==NULL ) return 1;

   snprintf(buffer, sizeof(buffer),"%s %d",l_month[cur_month-1],cur_year);
   write_xml_head(buffer, xml_fp);
	
   month_total_fragment();

   if (daily_stats) daily_total_fragment();

   if (hourly_stats) hourly_total_fragment();

   /* Do URL related stuff here, sorting appropriately                      */
   if ( (a_ctr=load_url_array(NULL)) )
   {
    if ( (u_array=malloc(sizeof(UNODEPTR)*(a_ctr))) !=NULL )
    {
     a_ctr=load_url_array(u_array);        /* load up our sort array        */
     if (ntop_urls || dump_urls)
     {
       qsort(u_array,a_ctr,sizeof(UNODEPTR),qs_url_cmph);
       if (ntop_urls) top_urls_fragment(0);   /* Top URL's (by hits)           */
       if (dump_urls) dump_all_urls();     /* Dump URLS tab file            */
     }
     if (ntop_urlsK)                       /* Top URL's (by kbytes)         */
      {qsort(u_array,a_ctr,sizeof(UNODEPTR),qs_url_cmpk); top_urls_fragment(1); }
     if (ntop_entry)                       /* Top Entry Pages               */
      {qsort(u_array,a_ctr,sizeof(UNODEPTR),qs_url_cmpn); top_entry_fragment(0);}
     if (ntop_exit)                        /* Top Exit Pages                */
      {qsort(u_array,a_ctr,sizeof(UNODEPTR),qs_url_cmpx); top_entry_fragment(1);}
     free(u_array);
    }
    else if (verbose) fprintf(stderr,"%s [u_array]\n",msg_nomem_tu); /* err */
   }

   /* do hostname (sites) related stuff here, sorting appropriately...      */
   if ( (a_ctr=load_site_array(NULL)) )
   {
    if ( (h_array=malloc(sizeof(HNODEPTR)*(a_ctr))) !=NULL )
    {
     a_ctr=load_site_array(h_array);       /* load up our sort array        */
     if (ntop_sites || dump_sites)
     {
       qsort(h_array,a_ctr,sizeof(HNODEPTR),qs_site_cmph);
       if (ntop_sites) top_sites_fragment(0); /* Top sites table (by hits)     */
       if (dump_sites) dump_all_sites();   /* Dump sites tab file           */
     }
     if (ntop_sitesK)                      /* Top Sites table (by kbytes)   */
     {
       qsort(h_array,a_ctr,sizeof(HNODEPTR),qs_site_cmpk);
       top_sites_fragment(1);
     }
     free(h_array);
    }
    else if (verbose) fprintf(stderr,"%s [h_array]\n",msg_nomem_ts); /* err */
   }

   /* do referrer related stuff here, sorting appropriately...              */
   if ( (a_ctr=load_ref_array(NULL)) )
   {
    if ( (r_array=malloc(sizeof(RNODEPTR)*(a_ctr))) != NULL)
    {
     a_ctr=load_ref_array(r_array);
     if (ntop_refs || dump_refs)
     {
       qsort(r_array,a_ctr,sizeof(RNODEPTR),qs_ref_cmph);
       if (ntop_refs) top_refs_fragment();   /* Top referrers table            */
       if (dump_refs) dump_all_refs();    /* Dump referrers tab file        */
     }
     free(r_array);
    }
    else if (verbose) fprintf(stderr,"%s [r_array]\n",msg_nomem_tr); /* err */
   }

   /* do search string related stuff, sorting appropriately...              */
   if ( (a_ctr=load_srch_array(NULL)) )
   {
    if ( (s_array=malloc(sizeof(SNODEPTR)*(a_ctr))) != NULL)
    {
     a_ctr=load_srch_array(s_array);
     if (ntop_search || dump_search)
     {
       qsort(s_array,a_ctr,sizeof(SNODEPTR),qs_srch_cmph);
       if (ntop_search) top_search_fragment(); /* top search strings table     */
       if (dump_search) dump_all_search();  /* dump search string tab file  */
     }
     free(s_array);
    }
    else if (verbose) fprintf(stderr,"%s [s_array]\n",msg_nomem_tsr);/* err */
   }

   /* do ident (username) related stuff here, sorting appropriately...      */
   if ( (a_ctr=load_ident_array(NULL)) )
   {
    if ( (i_array=malloc(sizeof(INODEPTR)*(a_ctr))) != NULL)
    {
     a_ctr=load_ident_array(i_array);
     if (ntop_users || dump_users)
     {
       qsort(i_array,a_ctr,sizeof(INODEPTR),qs_ident_cmph);
       if (ntop_users) top_users_fragment(); /* top usernames table            */
       if (dump_users) dump_all_users();  /* dump usernames tab file        */
     }
     free(i_array);
    }
    else if (verbose) fprintf(stderr,"%s [i_array]\n",msg_nomem_ti); /* err */
   }

   /* do user agent related stuff here, sorting appropriately...            */
   if ( (a_ctr=load_agent_array(NULL)) )
   {
    if ( (a_array=malloc(sizeof(ANODEPTR)*(a_ctr))) != NULL)
    {
     a_ctr=load_agent_array(a_array);
     if (ntop_agents || dump_agents)
     {
       qsort(a_array,a_ctr,sizeof(ANODEPTR),qs_agnt_cmph);
       if (ntop_agents) top_agents_fragment(); /* top user agents table        */
       if (dump_agents) dump_all_agents();  /* dump user agents tab file    */
     }
     free(a_array);
    }
    else if (verbose) fprintf(stderr,"%s [a_array]\n",msg_nomem_ta); /* err */
   }

   if (ntop_ctrys ) top_ctry_table();     /* top countries table            */

   write_xml_tail(xml_fp);               /* finish up the HTML document    */
   fclose(xml_fp);                        /* close the file                 */
   return (0);                            /* done...                        */
}
void write_xml_head(char *period, FILE *out_fp)
{
	NLISTPTR lptr;
	
	fprintf(xml_fp, "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n");
	fprintf(xml_fp, "<?xml-stylesheet type=\"text/xsl\" href=\"stats.xsl\" ?>\n");
	fprintf(xml_fp, "<stats sitename=\"%s\">\n",hname);
	fprintf(xml_fp, "\t<usage>\n");
}

void write_xml_tail(FILE *out_fp)
{
  fprintf(xml_fp, "\t</usage>\n</stats>\n");
}

/*********************************************/
/* HOURLY_TOTAL_FRAGMENT - hourly fragment   */
/*********************************************/

void hourly_total_fragment()
{
   int i,days_in_month;
   u_long avg_file=0;
   double avg_xfer=0.0;

   days_in_month=(l_day-f_day)+1;

   /* Hourly stats */

   fprintf(xml_fp,"\t\t<hourly>\n");

   for (i=0;i<24;i++)
   {
      fprintf(xml_fp, "\t\t\t<hour " \
         "id=\"%d\" " \
         "avg_hits=\"%lu\" total_hits=\"%lu\" percent_hits=\"%3.02f%%\" " \
         "avg_files=\"%lu\" total_files=\"%lu\" percent_files=\"%3.02f%%\" " \
         "avg_pages=\"%lu\" total_pages=\"%lu\" percent_pages=\"%3.02f%%\" " \
         "avg_kbytes=\"%.0f\" total_kbytes=\"%.0f\" percent_kbytes=\"%3.02f%%\" " \
         "/>\n",
         i, // id
         th_hit[i]/days_in_month,th_hit[i],PCENT(th_hit[i],t_hit), // hits
         th_file[i]/days_in_month,th_file[i],PCENT(th_file[i],t_file), // files
         th_page[i]/days_in_month,th_page[i],PCENT(th_page[i],t_page), // pages
         th_xfer[i]/days_in_month/1024,th_xfer[i]/1024,PCENT(th_xfer[i],t_xfer)); // kbytes
   }

   fprintf(xml_fp,"\t\t</hourly>\n");
}

/*********************************************/
/* TOP_SITES_FRAGMENT - generate top n table */
/*********************************************/

void top_sites_fragment(int flag)
{
   u_long cnt=0, h_reg=0, h_grp=0, h_hid=0, tot_num;
   int i;
   HNODEPTR hptr, *pointer;

   cnt=a_ctr; pointer=h_array;
   while(cnt--)
   {
      /* calculate totals */
      switch ((*pointer)->flag)
      {
         case OBJ_REG:   h_reg++;  break;
         case OBJ_GRP:   h_grp++;  break;
         case OBJ_HIDE:  h_hid++;  break;
      }
      pointer++;
   }

   if ( (tot_num=h_reg+h_grp)==0 ) return;              /* split if none    */
   i=(flag)?ntop_sitesK:ntop_sites;                     /* Hits or KBytes?? */
   if (tot_num > i) tot_num = i;                        /* get max to do... */

   if (flag) fprintf(xml_fp,"\t\t<top_sites_by_kbytes>\n");
   else      fprintf(xml_fp,"\t\t<top_sites_by_hits>\n");

   pointer=h_array; i=0;
   while(tot_num)
   {
      hptr=*pointer++;
      if (hptr->flag != OBJ_HIDE)
      {
        
         fprintf(xml_fp,"\t\t\t<site" \
             " id=\"%d\"" \
             " hits=\"%lu\" percent_hits=\"%3.02f%%\"" \
             " files=\"%lu\" percent_files=\"%3.02f%%\"" \
             " kbytes=\"%.0f\" percent_kbytes=\"%3.02f%%\"" \
             " visits=\"%lu\" percent_visits=\"%3.02f%%\"" \
             ">%s</site>\n", \
             i+1, \
             hptr->count,(t_hit==0)?0:((float)hptr->count/t_hit)*100.0, \
             hptr->files,(t_file==0)?0:((float)hptr->files/t_file)*100.0, \
             hptr->xfer/1024,(t_xfer==0)?0:((float)hptr->xfer/t_xfer)*100.0, \
             hptr->visit,(t_visit==0)?0:((float)hptr->visit/t_visit)*100.0,
             hptr->string);

         tot_num--;
         i++;
      }
   }

   if (flag) fprintf(xml_fp,"\t\t</top_sites_by_kbytes>\n");
   else      fprintf(xml_fp,"\t\t</top_sites_by_hits>\n");
}

/*********************************************/
/* ALL_SITES_PAGE - HTML page of all sites   */
/*********************************************/

int all_sites_page(u_long h_reg, u_long h_grp)
{
   HNODEPTR hptr, *pointer;
   char     site_fname[256], buffer[256];
   FILE     *out_fp;
   int      i=(h_grp)?1:0;

   /* generate file name */
   snprintf(site_fname, sizeof(site_fname),"site_%04d%02d.%s",cur_year,cur_month,html_ext);

   /* open file */
   if ( (out_fp=open_out_file(site_fname))==NULL ) return 0;

   snprintf(buffer, sizeof(buffer),"%s %d - %s",l_month[cur_month-1],cur_year,msg_h_sites);
   // write_html_head(buffer, out_fp);

   fprintf(out_fp,"<FONT SIZE=\"-1\"></CENTER><PRE>\n");

   fprintf(out_fp," %12s      %12s      %12s      %12s      %s\n",
           msg_h_hits, msg_h_files, msg_h_xfer, msg_h_visits, msg_h_hname);
   fprintf(out_fp,"----------------  ----------------  ----------------  " \
                  "----------------  --------------------\n\n");

   /* Do groups first (if any) */
   pointer=h_array;
   while(h_grp)
   {
      hptr=*pointer++;
      if (hptr->flag == OBJ_GRP)
      {
         fprintf(out_fp,
         "%-8lu %6.02f%%  %8lu %6.02f%%  %8.0f %6.02f%%  %8lu %6.02f%%  %s\n",
            hptr->count,
            (t_hit==0)?0:((float)hptr->count/t_hit)*100.0,hptr->files,
            (t_file==0)?0:((float)hptr->files/t_file)*100.0,hptr->xfer/1024,
            (t_xfer==0)?0:((float)hptr->xfer/t_xfer)*100.0,hptr->visit,
            (t_visit==0)?0:((float)hptr->visit/t_visit)*100.0,
            hptr->string);
         h_grp--;
      }
   }

   if (i) fprintf(out_fp,"\n");

   /* Now do individual sites (if any) */
   pointer=h_array;
   if (!hide_sites) while(h_reg)
   {
      hptr=*pointer++;
      if (hptr->flag == OBJ_REG)
      {
         fprintf(out_fp,
         "%-8lu %6.02f%%  %8lu %6.02f%%  %8.0f %6.02f%%  %8lu %6.02f%%  %s\n",
            hptr->count,
            (t_hit==0)?0:((float)hptr->count/t_hit)*100.0,hptr->files,
            (t_file==0)?0:((float)hptr->files/t_file)*100.0,hptr->xfer/1024,
            (t_xfer==0)?0:((float)hptr->xfer/t_xfer)*100.0,hptr->visit,
            (t_visit==0)?0:((float)hptr->visit/t_visit)*100.0,
            hptr->string);
         h_reg--;
      }
   }

   fprintf(out_fp,"</PRE></FONT>\n");
   // write_html_tail(out_fp);
   fclose(out_fp);
   return 1;
}

/*********************************************/
/* TOP_URLS_TABLE - generate top n table     */
/*********************************************/

void top_urls_fragment(int flag)
{
   u_long cnt=0,u_reg=0,u_grp=0,u_hid=0, tot_num;
   int i;
   UNODEPTR uptr, *pointer;

   cnt=a_ctr; pointer=u_array;
   while (cnt--)
   {
      /* calculate totals */
      switch ((*pointer)->flag)
      {
         case OBJ_REG:  u_reg++;  break;
         case OBJ_GRP:  u_grp++;  break;
         case OBJ_HIDE: u_hid++;  break;
      }
      pointer++;
   }

   if ( (tot_num=u_reg+u_grp)==0 ) return;              /* split if none    */
   i=(flag)?ntop_urlsK:ntop_urls;                       /* Hits or KBytes?? */
   if (tot_num > i) tot_num = i;                        /* get max to do... */

   if (flag) fprintf(xml_fp,"\t\t<top_urls_by_kbytes>\n");
   else      fprintf(xml_fp,"\t\t<top_urls_by_hits>\n");

   pointer=u_array; i=0;
   while (tot_num)
   {
      uptr=*pointer++;             /* point to the URL node */
      if (uptr->flag != OBJ_HIDE)
      {
         fprintf(xml_fp, \
             "\t\t\t<url" \
             " id=\"%d\"" \
             " hits=\"%lu\" percent_hits=\"%3.02f%%\"" \
             " kbytes=\"%.0f\" percent_kbytes=\"%3.02f%%\"" \
             ">%s</url>\n", \
             i+1, \
             uptr->count,(t_hit==0)?0:((float)uptr->count/t_hit)*100.0, \
             uptr->xfer/1024,(t_xfer==0)?0:((float)uptr->xfer/t_xfer)*100.0, \
             uptr->string);

         tot_num--;
         i++;
      } 
   }

   if (flag) fprintf(xml_fp,"\t\t</top_urls_by_kbytes>\n");
   else      fprintf(xml_fp,"\t\t</top_urls_by_hits>\n");
}

/*********************************************/
/* ALL_URLS_PAGE - HTML page of all urls     */
/*********************************************/

int all_urls_page(u_long u_reg, u_long u_grp)
{
   UNODEPTR uptr, *pointer;
   char     url_fname[256], buffer[256];
   FILE     *out_fp;
   int      i=(u_grp)?1:0;

   /* generate file name */
   snprintf(url_fname, sizeof(url_fname),"url_%04d%02d.%s",cur_year,cur_month,html_ext);

   /* open file */
   if ( (out_fp=open_out_file(url_fname))==NULL ) return 0;

   snprintf(buffer, sizeof(buffer),"%s %d - %s",l_month[cur_month-1],cur_year,msg_h_url);
   // write_html_head(buffer, out_fp);

   fprintf(out_fp,"<FONT SIZE=\"-1\"></CENTER><PRE>\n");

   fprintf(out_fp," %12s      %12s      %s\n",
           msg_h_hits,msg_h_xfer,msg_h_url);
   fprintf(out_fp,"----------------  ----------------  " \
                  "--------------------\n\n");

   /* do groups first (if any) */
   pointer=u_array;
   while (u_grp)
   {
      uptr=*pointer++;
      if (uptr->flag == OBJ_GRP)
      {
         fprintf(out_fp,"%-8lu %6.02f%%  %8.0f %6.02f%%  %s\n",
            uptr->count,
            (t_hit==0)?0:((float)uptr->count/t_hit)*100.0,
            uptr->xfer/1024,
            (t_xfer==0)?0:((float)uptr->xfer/t_xfer)*100.0,
            uptr->string);
         u_grp--;
      }
   }

   if (i) fprintf(out_fp,"\n");

   /* now do invididual sites (if any) */
   pointer=u_array;
   while (u_reg)
   {
      uptr=*pointer++;
      if (uptr->flag == OBJ_REG)
      {
         fprintf(out_fp,"%-8lu %6.02f%%  %8.0f %6.02f%%  %s\n",
            uptr->count,
            (t_hit==0)?0:((float)uptr->count/t_hit)*100.0,
            uptr->xfer/1024,
            (t_xfer==0)?0:((float)uptr->xfer/t_xfer)*100.0,
            uptr->string);
         u_reg--;
      }
   }

   fprintf(out_fp,"</PRE></FONT>\n");
   // write_html_tail(out_fp);
   fclose(out_fp);
   return 1;
}

/**********************************************/
/* TOP_ENTRY_FRAGMENT - top n entry/exit urls */
/**********************************************/

void top_entry_fragment(int flag)
{
   u_long cnt=0, u_entry=0, u_exit=0, tot_num;
   u_long t_entry=0, t_exit=0;
   int i;
   UNODEPTR uptr, *pointer;

   cnt=a_ctr; pointer=u_array;
   while (cnt--)
   {
      if ((*pointer)->flag == OBJ_REG )
      {
         if ((*pointer)->entry)
            {  u_entry++; t_entry+=(*pointer)->entry; }
         if ((*pointer)->exit)
            { u_exit++;   t_exit += (*pointer)->exit;  }
      }
      pointer++;
   }

   /* calculate how many we have */
   tot_num=(flag)?u_exit:u_entry;
   if (flag) { if (tot_num > ntop_exit ) tot_num=ntop_exit;  }
   else      { if (tot_num > ntop_entry) tot_num=ntop_entry; }

   /* return if none to do */
   if (!tot_num) return;

   if (flag) fprintf(xml_fp,"\t\t<top_entry_urls>\n");
   else      fprintf(xml_fp,"\t\t<top_exit_urls>\n");

   pointer=u_array; i=0;
   while (tot_num)
   {
      uptr=*pointer++;
      if (uptr->flag != OBJ_HIDE)
      {
         fprintf(xml_fp,
             "\t\t\t<url id=\"%d\"" \
             " hits=\"%lu\" percent_hits=\"%3.02f%%\"" \
             " visits=\"%lu\" percent_visits=\"%3.02f%%\"" \
             ">%s</url>\n", \
             i+1, \
             uptr->count,(t_hit==0)?0:((float)uptr->count/t_hit)*100.0, \
             (flag)?uptr->exit:uptr->entry,(flag)?((t_exit==0)?0:((float)uptr->exit/t_exit)*100.0) \
               :((t_entry==0)?0:((float)uptr->entry/t_entry)*100.0),
             uptr->string);

         tot_num--;
         i++;
      }
   }

   if (flag) fprintf(xml_fp,"\t\t</top_entry_urls>\n");
   else      fprintf(xml_fp,"\t\t</top_exit_urls>\n");
}

/*********************************************/
/* TOP_REFS_FRAGMENT - generate top n table  */
/*********************************************/

void top_refs_fragment()
{
   u_long cnt=0, r_reg=0, r_grp=0, r_hid=0, tot_num;
   int i;
   RNODEPTR rptr, *pointer;

   if (t_ref==0) return;        /* return if none to process */

   cnt=a_ctr; pointer=r_array;
   while(cnt--)
   {
      /* calculate totals */
      switch ((*pointer)->flag)
      {
         case OBJ_REG:  r_reg++;  break;
         case OBJ_HIDE: r_hid++;  break;
         case OBJ_GRP:  r_grp++;  break;
      }
      pointer++;
   }

   if ( (tot_num=r_reg+r_grp)==0 ) return;              /* split if none    */
   if (tot_num > ntop_refs) tot_num=ntop_refs;          /* get max to do... */

   fprintf(xml_fp,"\t\t<refs>\n");

   pointer=r_array; i=0;
   while(tot_num)
   {
      rptr=*pointer++;
      if (rptr->flag != OBJ_HIDE)
      {
         fprintf(xml_fp,"\t\t\t<ref" \
             " id=\"%d\"" \
             " hits=\"%lu\"" \
             " percent_hits=\"%3.02f%%\"" \
             ">%s</ref>\n", \
             i+1,
             rptr->count,(t_hit==0)?0:((float)rptr->count/t_hit)*100.0,
             rptr->string);

         tot_num--;
         i++;
      }
   }

   fprintf(xml_fp,"\t\t</refs>\n");
}

/*********************************************/
/* ALL_REFS_PAGE - HTML page of all refs     */
/*********************************************/

int all_refs_page(u_long r_reg, u_long r_grp)
{
   RNODEPTR rptr, *pointer;
   char     ref_fname[256], buffer[256];
   FILE     *out_fp;
   int      i=(r_grp)?1:0;

   /* generate file name */
   snprintf(ref_fname, sizeof(ref_fname),"ref_%04d%02d.%s",cur_year,cur_month,html_ext);

   /* open file */
   if ( (out_fp=open_out_file(ref_fname))==NULL ) return 0;

   snprintf(buffer, sizeof(buffer),"%s %d - %s",l_month[cur_month-1],cur_year,msg_h_ref);
   // write_html_head(buffer, out_fp);

   fprintf(out_fp,"<FONT SIZE=\"-1\"></CENTER><PRE>\n");

   fprintf(out_fp," %12s      %s\n",msg_h_hits,msg_h_ref);
   fprintf(out_fp,"----------------  --------------------\n\n");

   /* do groups first (if any) */
   pointer=r_array;
   while(r_grp)
   {
      rptr=*pointer++;
      if (rptr->flag == OBJ_GRP)
      {
         fprintf(out_fp,"%-8lu %6.02f%%  %s\n",
            rptr->count,
            (t_hit==0)?0:((float)rptr->count/t_hit)*100.0,
            rptr->string);
         r_grp--;
      }
   }

   if (i) fprintf(out_fp,"\n");

   pointer=r_array;
   while(r_reg)
   {
      rptr=*pointer++;
      if (rptr->flag == OBJ_REG)
      {
         fprintf(out_fp,"%-8lu %6.02f%%  %s\n",
            rptr->count,
            (t_hit==0)?0:((float)rptr->count/t_hit)*100.0,
            rptr->string);
         r_reg--;
      }
   }

   fprintf(out_fp,"</PRE></FONT>\n");
   // write_html_tail(out_fp);
   fclose(out_fp);
   return 1;
}

/**********************************************/
/* TOP_AGENTS_FRAGMENT - generate top n table */
/**********************************************/

void top_agents_fragment()
{
   u_long cnt, a_reg=0, a_grp=0, a_hid=0, tot_num;
   int i;
   ANODEPTR aptr, *pointer;

   if (t_agent == 0) return;    /* don't bother if we don't have any */

   cnt=a_ctr; pointer=a_array;
   while(cnt--)
   {
      /* calculate totals */
      switch ((*pointer)->flag)
      {
         case OBJ_REG:   a_reg++;  break;
         case OBJ_GRP:   a_grp++;  break;
         case OBJ_HIDE:  a_hid++;  break;
      }
      pointer++;
   }

   if ( (tot_num=a_reg+a_grp)==0 ) return;              /* split if none    */
   if (tot_num > ntop_agents) tot_num=ntop_agents;      /* get max to do... */

   fprintf(xml_fp,"\t\t<agents>\n");

   pointer=a_array; i=0;
   while(tot_num)
   {
      aptr=*pointer++;
      if (aptr->flag != OBJ_HIDE)
      {
         fprintf(xml_fp, \
             "\t\t\t<agent" \
             " id=\"%d\"" \
             " hits=\"%lu\"" \
             " percent_hits=\"%3.02f%%\"" \
             ">%s</agent>\n", \
             i+1,
             aptr->count,(t_hit==0)?0:((float)aptr->count/t_hit)*100.0,
             aptr->string);

         tot_num--;
         i++;
      }
   }
   
   fprintf(xml_fp,"\t\t</agents>\n");
}

/*********************************************/
/* ALL_AGENTS_PAGE - HTML user agent page    */
/*********************************************/

int all_agents_page(u_long a_reg, u_long a_grp)
{
   ANODEPTR aptr, *pointer;
   char     agent_fname[256], buffer[256];
   FILE     *out_fp;
   int      i=(a_grp)?1:0;

   /* generate file name */
   snprintf(agent_fname, sizeof(agent_fname),"agent_%04d%02d.%s",cur_year,cur_month,html_ext);

   /* open file */
   if ( (out_fp=open_out_file(agent_fname))==NULL ) return 0;

   snprintf(buffer, sizeof(buffer),"%s %d - %s",l_month[cur_month-1],cur_year,msg_h_agent);
   // write_html_head(buffer, out_fp);

   fprintf(out_fp,"<FONT SIZE=\"-1\"></CENTER><PRE>\n");

   fprintf(out_fp," %12s      %s\n",msg_h_hits,msg_h_agent);
   fprintf(out_fp,"----------------  ----------------------\n\n");

   /* do groups first (if any) */
   pointer=a_array;
   while(a_grp)
   {
      aptr=*pointer++;
      if (aptr->flag == OBJ_GRP)
      {
         fprintf(out_fp,"%-8lu %6.02f%%  %s\n",
             aptr->count,
             (t_hit==0)?0:((float)aptr->count/t_hit)*100.0,
             aptr->string);
         a_grp--;
      }
   }

   if (i) fprintf(out_fp,"\n");

   pointer=a_array;
   while(a_reg)
   {
      aptr=*pointer++;
      if (aptr->flag == OBJ_REG)
      {
         fprintf(out_fp,"%-8lu %6.02f%%  %s\n",
             aptr->count,
             (t_hit==0)?0:((float)aptr->count/t_hit)*100.0,
             aptr->string);
         a_reg--;
      }
   }

   fprintf(out_fp,"</PRE></FONT>\n");
   // write_html_tail(out_fp);
   fclose(out_fp);
   return 1;
}

/**********************************************/
/* TOP_SEARCH_FRAGMENT - generate top n table */
/**********************************************/

void top_search_fragment()
{
   u_long   cnt,t_val=0, tot_num;
   int      i;
   SNODEPTR sptr, *pointer;

   if ( (t_ref==0)||(a_ctr==0)) return;   /* don't bother if none to do    */

   cnt=tot_num=a_ctr; pointer=s_array;
   while(cnt--)
   {
      t_val+=(*pointer)->count;
      pointer++;
   }

   if ( tot_num > ntop_search) tot_num=ntop_search;

   fprintf(xml_fp,"\t\t<keywords>\n");

   pointer=s_array; i=0;
   while(tot_num)
   {
      sptr=*pointer++;
      fprintf(xml_fp, \
         "\t\t\t<keyword" \
         " id=\"%d\"" \
         " hits=\"%lu\" percent_hits=\"%3.02f%%\"" \
         ">%s</keyword>\n", \
         i+1, \
         sptr->count,(t_val==0)?0:((float)sptr->count/t_val)*100.0, \
         sptr->string);

      tot_num--;
      i++;
   }

   fprintf(xml_fp,"\t\t</keywords>\n");
}

/*********************************************/
/* ALL_SEARCH_PAGE - HTML for search strings */
/*********************************************/

int all_search_page(u_long tot_num, u_long t_val)
{
   SNODEPTR sptr, *pointer;
   char     search_fname[256], buffer[256];
   FILE     *out_fp;

   if (!tot_num) return 0;

   /* generate file name */
   snprintf(search_fname, sizeof(search_fname),"search_%04d%02d.%s",cur_year,cur_month,html_ext);

   /* open file */
   if ( (out_fp=open_out_file(search_fname))==NULL ) return 0;

   snprintf(buffer, sizeof(buffer),"%s %d - %s",l_month[cur_month-1],cur_year,msg_h_search);
   // write_html_head(buffer, out_fp);

   fprintf(out_fp,"<FONT SIZE=\"-1\"></CENTER><PRE>\n");

   fprintf(out_fp," %12s      %s\n",msg_h_hits,msg_h_search);
   fprintf(out_fp,"----------------  ----------------------\n\n");

   pointer=s_array;
   while(tot_num)
   {
      sptr=*pointer++;
      fprintf(out_fp,"%-8lu %6.02f%%  %s\n",
         sptr->count,
         (t_val==0)?0:((float)sptr->count/t_val)*100.0,
         sptr->string);
      tot_num--;
   }
   fprintf(out_fp,"</PRE></FONT>\n");
   // write_html_tail(out_fp);
   fclose(out_fp);
   return 1;
}

/*********************************************/
/* TOP_USERS_FRAGMENT - generate top n table */
/*********************************************/

void top_users_fragment()
{
   u_long cnt=0, i_reg=0, i_grp=0, i_hid=0, tot_num;
   int i;
   INODEPTR iptr, *pointer;

   cnt=a_ctr; pointer=i_array;
   while(cnt--)
   {
      /* calculate totals */
      switch ((*pointer)->flag)
      {
         case OBJ_REG:   i_reg++;  break;
         case OBJ_GRP:   i_grp++;  break;
         case OBJ_HIDE:  i_hid++;  break;
      }
      pointer++;
   }

   if ( (tot_num=i_reg+i_grp)==0 ) return;              /* split if none    */
   if (tot_num > ntop_users) tot_num = ntop_users;

   fprintf(out_fp,"<A NAME=\"TOPUSERS\"></A>\n");       /* now do <A> tag   */

   fprintf(out_fp,"<TABLE WIDTH=510 BORDER=2 CELLSPACING=1 CELLPADDING=1>\n");
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   fprintf(out_fp,"<TR><TH BGCOLOR=\"%s\" ALIGN=CENTER COLSPAN=10>" \
           "%s %lu %s %lu %s</TH></TR>\n",
           GREY,msg_top_top, tot_num, msg_top_of, t_user, msg_top_i);
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   fprintf(out_fp,"<TR><TH BGCOLOR=\"%s\" ALIGN=center>"                   \
          "<FONT SIZE=\"-1\">#</FONT></TH>\n",GREY);
   fprintf(out_fp,"<TH BGCOLOR=\"%s\" ALIGN=center COLSPAN=2>"             \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",DKGREEN,msg_h_hits);
   fprintf(out_fp,"<TH BGCOLOR=\"%s\" ALIGN=center COLSPAN=2>"             \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",LTBLUE,msg_h_files);
   fprintf(out_fp,"<TH BGCOLOR=\"%s\" ALIGN=center COLSPAN=2>"             \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",RED,msg_h_xfer);
   fprintf(out_fp,"<TH BGCOLOR=\"%s\" ALIGN=center COLSPAN=2>"             \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",YELLOW,msg_h_visits);
   fprintf(out_fp,"<TH BGCOLOR=\"%s\" ALIGN=center>"                       \
          "<FONT SIZE=\"-1\">%s</FONT></TH></TR>\n",CYAN,msg_h_uname);
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");

   pointer=i_array; i=0;
   while(tot_num)
   {
      iptr=*pointer++;
      if (iptr->flag != OBJ_HIDE)
      {
         /* shade grouping? */
         if (shade_groups && (iptr->flag==OBJ_GRP))
            fprintf(out_fp,"<TR BGCOLOR=\"%s\">\n", GRPCOLOR);
         else fprintf(out_fp,"<TR>\n");

         fprintf(out_fp,
              "<TD ALIGN=center><FONT SIZE=\"-1\"><B>%d</B></FONT></TD>\n"  \
              "<TD ALIGN=right><FONT SIZE=\"-1\"><B>%lu</B></FONT></TD>\n"  \
              "<TD ALIGN=right><FONT SIZE=\"-2\">%3.02f%%</FONT></TD>\n"    \
              "<TD ALIGN=right><FONT SIZE=\"-1\"><B>%lu</B></FONT></TD>\n"  \
              "<TD ALIGN=right><FONT SIZE=\"-2\">%3.02f%%</FONT></TD>\n"    \
              "<TD ALIGN=right><FONT SIZE=\"-1\"><B>%.0f</B></FONT></TD>\n" \
              "<TD ALIGN=right><FONT SIZE=\"-2\">%3.02f%%</FONT></TD>\n"    \
              "<TD ALIGN=right><FONT SIZE=\"-1\"><B>%lu</B></FONT></TD>\n"  \
              "<TD ALIGN=right><FONT SIZE=\"-2\">%3.02f%%</FONT></TD>\n"    \
              "<TD ALIGN=left NOWRAP><FONT SIZE=\"-1\">",
              i+1,iptr->count,
              (t_hit==0)?0:((float)iptr->count/t_hit)*100.0,iptr->files,
              (t_file==0)?0:((float)iptr->files/t_file)*100.0,iptr->xfer/1024,
              (t_xfer==0)?0:((float)iptr->xfer/t_xfer)*100.0,iptr->visit,
              (t_visit==0)?0:((float)iptr->visit/t_visit)*100.0);

         if ((iptr->flag==OBJ_GRP)&&hlite_groups)
             fprintf(out_fp,"<STRONG>%s</STRONG></FONT></TD></TR>\n",
               iptr->string);
         else fprintf(out_fp,"%s</FONT></TD></TR>\n",
               iptr->string);
         tot_num--;
         i++;
      }
   }

   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   if ( (all_users) && ((i_reg+i_grp)>ntop_users) )
   {
      if (all_users_page(i_reg, i_grp))
      {
         fprintf(out_fp,"<TR BGCOLOR=\"%s\">",GRPCOLOR);
         fprintf(out_fp,"<TD COLSPAN=10 ALIGN=\"center\">\n");
         fprintf(out_fp,"<FONT SIZE=\"-1\">");
         fprintf(out_fp,"<A HREF=\"./user_%04d%02d.%s\">",
            cur_year,cur_month,html_ext);
         fprintf(out_fp,"%s</A></TD></TR>\n",msg_v_users);
      }
   }
   fprintf(out_fp,"</TABLE>\n<P>\n");
}

/*********************************************/
/* ALL_USERS_PAGE - HTML of all usernames    */
/*********************************************/

int all_users_page(u_long i_reg, u_long i_grp)
{
   INODEPTR iptr, *pointer;
   char     user_fname[256], buffer[256];
   FILE     *out_fp;
   int      i=(i_grp)?1:0;

   /* generate file name */
   snprintf(user_fname, sizeof(user_fname),"user_%04d%02d.%s",cur_year,cur_month,html_ext);

   /* open file */
   if ( (out_fp=open_out_file(user_fname))==NULL ) return 0;

   snprintf(buffer, sizeof(buffer),"%s %d - %s",l_month[cur_month-1],cur_year,msg_h_uname);
   // write_html_head(buffer, out_fp);

   fprintf(out_fp,"<FONT SIZE=\"-1\"></CENTER><PRE>\n");

   fprintf(out_fp," %12s      %12s      %12s      %12s      %s\n",
           msg_h_hits, msg_h_files, msg_h_xfer, msg_h_visits, msg_h_uname);
   fprintf(out_fp,"----------------  ----------------  ----------------  " \
                  "----------------  --------------------\n\n");

   /* Do groups first (if any) */
   pointer=i_array;
   while(i_grp)
   {
      iptr=*pointer++;
      if (iptr->flag == OBJ_GRP)
      {
         fprintf(out_fp,
         "%-8lu %6.02f%%  %8lu %6.02f%%  %8.0f %6.02f%%  %8lu %6.02f%%  %s\n",
            iptr->count,
            (t_hit==0)?0:((float)iptr->count/t_hit)*100.0,iptr->files,
            (t_file==0)?0:((float)iptr->files/t_file)*100.0,iptr->xfer/1024,
            (t_xfer==0)?0:((float)iptr->xfer/t_xfer)*100.0,iptr->visit,
            (t_visit==0)?0:((float)iptr->visit/t_visit)*100.0,
            iptr->string);
         i_grp--;
      }
   }

   if (i) fprintf(out_fp,"\n");

   /* Now do individual users (if any) */
   pointer=i_array;
   while(i_reg)
   {
      iptr=*pointer++;
      if (iptr->flag == OBJ_REG)
      {
         fprintf(out_fp,
         "%-8lu %6.02f%%  %8lu %6.02f%%  %8.0f %6.02f%%  %8lu %6.02f%%  %s\n",
            iptr->count,
            (t_hit==0)?0:((float)iptr->count/t_hit)*100.0,iptr->files,
            (t_file==0)?0:((float)iptr->files/t_file)*100.0,iptr->xfer/1024,
            (t_xfer==0)?0:((float)iptr->xfer/t_xfer)*100.0,iptr->visit,
            (t_visit==0)?0:((float)iptr->visit/t_visit)*100.0,
            iptr->string);
         i_reg--;
      }
   }

   fprintf(out_fp,"</PRE></FONT>\n");
   // write_html_tail(out_fp);
   fclose(out_fp);
   return 1;
}

/*********************************************/
/* TOP_CTRY_TABLE - top countries table      */
/*********************************************/

void top_ctry_table()
{
   int i,j,x,tot_num=0,tot_ctry=0;
   int ctry_fnd;
   u_long idx;
   HNODEPTR hptr;
   char *domain;
   u_long pie_data[10];
   char   *pie_legend[10];
   char   pie_title[48];
   char   pie_fname[48];

   extern int ctry_graph;  /* include external flag */

   /* scan hash table adding up domain totals */
   for (i=0;i<MAXHASH;i++)
   {
      hptr=sm_htab[i];
      while (hptr!=NULL)
      {
         if (hptr->flag != OBJ_GRP)   /* ignore group totals */
         {
            domain = hptr->string+strlen(hptr->string)-1;
            while ( (*domain!='.')&&(domain!=hptr->string)) domain--;
            if ((domain==hptr->string)||(isdigit((int)*++domain)))
            {
               ctry[0].count+=hptr->count;
               ctry[0].files+=hptr->files;
               ctry[0].xfer +=hptr->xfer;
            }
            else
            {
               ctry_fnd=0;
               idx=ctry_idx(domain);
               for (j=0;ctry[j].desc;j++)
               {
                  if (idx==ctry[j].idx)
                  {
                     ctry[j].count+=hptr->count;
                     ctry[j].files+=hptr->files;
                     ctry[j].xfer +=hptr->xfer;
                     ctry_fnd=1;
                     break;
                  }
               }
               if (!ctry_fnd)
               {
                  ctry[0].count+=hptr->count;
                  ctry[0].files+=hptr->files;
                  ctry[0].xfer +=hptr->xfer;
               }
            }
         }
         hptr=hptr->next;
      }
   }

   for (i=0;ctry[i].desc;i++)
   {
      if (ctry[i].count!=0) tot_ctry++;
      for (j=0;j<ntop_ctrys;j++)
      {
         if (top_ctrys[j]==NULL) { top_ctrys[j]=&ctry[i]; break; }
         else
         {
            if (ctry[i].count > top_ctrys[j]->count)
            {
               for (x=ntop_ctrys-1;x>j;x--)
                  top_ctrys[x]=top_ctrys[x-1];
               top_ctrys[x]=&ctry[i];
               break;
            }
         }
      }
   }

   /* put our anchor tag first... */
   fprintf(out_fp,"<A NAME=\"TOPCTRYS\"></A>\n");

   /* generate pie chart if needed */
   if (ctry_graph)
   {
      for (i=0;i<10;i++) pie_data[i]=0;             /* init data array      */
      if (ntop_ctrys<10) j=ntop_ctrys; else j=10;   /* ensure data size     */

      for (i=0;i<j;i++)
      {
         pie_data[i]=top_ctrys[i]->count;           /* load the array       */
         pie_legend[i]=top_ctrys[i]->desc;
      }
      snprintf(pie_title, sizeof(pie_title),"%s %s %d",msg_ctry_use,l_month[cur_month-1],cur_year);
      snprintf(pie_fname, sizeof(pie_fname),"ctry_usage_%04d%02d.png",cur_year,cur_month);

      //pie_chart(pie_fname,pie_title,t_hit,pie_data,pie_legend);  /* do it   */

      /* put the image tag in the page */
      fprintf(out_fp,"<IMG SRC=\"%s\" ALT=\"%s\" " \
                  "HEIGHT=300 WIDTH=512><P>\n",pie_fname,pie_title);
   }

   /* Now do the table */
   for (i=0;i<ntop_ctrys;i++) if (top_ctrys[i]->count!=0) tot_num++;
   fprintf(out_fp,"<TABLE WIDTH=510 BORDER=2 CELLSPACING=1 CELLPADDING=1>\n");
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   fprintf(out_fp,"<TR><TH BGCOLOR=\"%s\" ALIGN=CENTER COLSPAN=8>"         \
           "%s %d %s %d %s</TH></TR>\n",
           GREY,msg_top_top,tot_num,msg_top_of,tot_ctry,msg_top_c);
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   fprintf(out_fp,"<TR><TH BGCOLOR=\"%s\" ALIGN=center>"                   \
          "<FONT SIZE=\"-1\">#</FONT></TH>\n",GREY);
   fprintf(out_fp,"<TH BGCOLOR=\"%s\" ALIGN=center COLSPAN=2>"             \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",DKGREEN,msg_h_hits);
   fprintf(out_fp,"<TH BGCOLOR=\"%s\" ALIGN=center COLSPAN=2>"             \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",LTBLUE,msg_h_files);
   fprintf(out_fp,"<TH BGCOLOR=\"%s\" ALIGN=center COLSPAN=2>"             \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",RED,msg_h_xfer);
   fprintf(out_fp,"<TH BGCOLOR=\"%s\" ALIGN=center>"                       \
          "<FONT SIZE=\"-1\">%s</FONT></TH></TR>\n",CYAN,msg_h_ctry);
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   for (i=0;i<ntop_ctrys;i++)
   {
      if (top_ctrys[i]->count!=0)
      fprintf(out_fp,"<TR>"                                                \
              "<TD ALIGN=center><FONT SIZE=\"-1\"><B>%d</B></FONT></TD>\n" \
              "<TD ALIGN=right><FONT SIZE=\"-1\"><B>%lu</B></FONT></TD>\n" \
              "<TD ALIGN=right><FONT SIZE=\"-2\">%3.02f%%</FONT></TD>\n"   \
              "<TD ALIGN=right><FONT SIZE=\"-1\"><B>%lu</B></FONT></TD>\n" \
              "<TD ALIGN=right><FONT SIZE=\"-2\">%3.02f%%</FONT></TD>\n"   \
              "<TD ALIGN=right><FONT SIZE=\"-1\"><B>%.0f</B></FONT></TD>\n" \
              "<TD ALIGN=right><FONT SIZE=\"-2\">%3.02f%%</FONT></TD>\n"   \
              "<TD ALIGN=left NOWRAP><FONT SIZE=\"-1\">%s</FONT></TD></TR>\n",
              i+1,top_ctrys[i]->count,
              (t_hit==0)?0:((float)top_ctrys[i]->count/t_hit)*100.0,
              top_ctrys[i]->files,
              (t_file==0)?0:((float)top_ctrys[i]->files/t_file)*100.0,
              top_ctrys[i]->xfer/1024,
              (t_xfer==0)?0:((float)top_ctrys[i]->xfer/t_xfer)*100.0,
              top_ctrys[i]->desc);
   }
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   fprintf(out_fp,"</TABLE>\n<P>\n");
}

/*********************************************/
/* DUMP_ALL_SITES - dump sites to tab file   */
/*********************************************/

void dump_all_sites()
{
   HNODEPTR hptr, *pointer;
   FILE     *out_fp;
   char     filename[256];
   u_long   cnt=a_ctr;

   /* generate file name */
   snprintf(filename, sizeof(filename),"%s/site_%04d%02d.%s",
      (dump_path)?dump_path:".",cur_year,cur_month,dump_ext);

   /* open file */
   if ( (out_fp=open_out_file(filename))==NULL ) return;

   /* need a header? */
   if (dump_header)
   {
      fprintf(out_fp,"%s\t%s\t%s\t%s\t%s\n",
       msg_h_hits,msg_h_files,msg_h_xfer,msg_h_visits,msg_h_hname); 
   }

   /* dump 'em */
   pointer=h_array;
   while (cnt)
   {
      hptr=*pointer++;
      if (hptr->flag != OBJ_GRP)
      {
         fprintf(out_fp,
         "%lu\t%lu\t%.0f\t%lu\t%s\n",
            hptr->count,hptr->files,hptr->xfer/1024,
            hptr->visit,hptr->string);
      }
      cnt--;
   }
   fclose(out_fp);
   return;
}

/*********************************************/
/* DUMP_ALL_URLS - dump all urls to tab file */
/*********************************************/

void dump_all_urls()
{
   UNODEPTR uptr, *pointer;
   FILE     *out_fp;
   char     filename[256];
   u_long   cnt=a_ctr;

   /* generate file name */
   snprintf(filename, sizeof(filename),"%s/url_%04d%02d.%s",
      (dump_path)?dump_path:".",cur_year,cur_month,dump_ext);

   /* open file */
   if ( (out_fp=open_out_file(filename))==NULL ) return;

   /* need a header? */
   if (dump_header)
   {
      fprintf(out_fp,"%s\t%s\t%s\n",msg_h_hits,msg_h_xfer,msg_h_url);
   }

   /* dump 'em */
   pointer=u_array;
   while (cnt)
   {
      uptr=*pointer++;
      if (uptr->flag != OBJ_GRP)
      {
         fprintf(out_fp,"%lu\t%.0f\t%s\n",
            uptr->count,uptr->xfer/1024,uptr->string);
      }
      cnt--;
   }
   fclose(out_fp);
   return;
}

/*********************************************/
/* DUMP_ALL_REFS - dump all refs to tab file */
/*********************************************/

void dump_all_refs()
{
   RNODEPTR rptr, *pointer;
   FILE     *out_fp;
   char     filename[256];
   u_long   cnt=a_ctr;

   /* generate file name */
   snprintf(filename, sizeof(filename),"%s/ref_%04d%02d.%s",
      (dump_path)?dump_path:".",cur_year,cur_month,dump_ext);

   /* open file */
   if ( (out_fp=open_out_file(filename))==NULL ) return;

   /* need a header? */
   if (dump_header)
   {
      fprintf(out_fp,"%s\t%s\n",msg_h_hits,msg_h_ref);
   }

   /* dump 'em */
   pointer=r_array;
   while(cnt)
   {
      rptr=*pointer++;
      if (rptr->flag != OBJ_GRP)
      {
         fprintf(out_fp,"%lu\t%s\n",rptr->count, rptr->string);
      }
      cnt--;
   }
   fclose(out_fp);
   return;
}

/*********************************************/
/* DUMP_ALL_AGENTS - dump agents htab file   */
/*********************************************/

void dump_all_agents()
{
   ANODEPTR aptr, *pointer;
   FILE     *out_fp;
   char     filename[256];
   u_char   cnt=a_ctr;

   /* generate file name */
   snprintf(filename, sizeof(filename),"%s/agent_%04d%02d.%s",
      (dump_path)?dump_path:".",cur_year,cur_month,dump_ext);

   /* open file */
   if ( (out_fp=open_out_file(filename))==NULL ) return;

   /* need a header? */
   if (dump_header)
   {
      fprintf(out_fp,"%s\t%s\n",msg_h_hits,msg_h_agent);
   }

   /* dump 'em */
   pointer=a_array;
   while(cnt)
   {
      aptr=*pointer++;
      if (aptr->flag != OBJ_GRP)
      {
         fprintf(out_fp,"%lu\t%s\n",aptr->count,aptr->string);
      }
      cnt--;
   }
   fclose(out_fp);
   return;
}

/*********************************************/
/* DUMP_ALL_USERS - dump username tab file   */
/*********************************************/

void dump_all_users()
{
   INODEPTR iptr, *pointer;
   FILE     *out_fp;
   char     filename[256];
   u_long   cnt=a_ctr;

   /* generate file name */
   snprintf(filename, sizeof(filename),"%s/user_%04d%02d.%s",
      (dump_path)?dump_path:".",cur_year,cur_month,dump_ext);

   /* open file */
   if ( (out_fp=open_out_file(filename))==NULL ) return;

   /* need a header? */
   if (dump_header)
   {
      fprintf(out_fp,"%s\t%s\t%s\t%s\t%s\n",
         msg_h_hits,msg_h_files,msg_h_xfer,msg_h_visits,msg_h_uname);
   }

   /* dump 'em */
   pointer=i_array;
   while(cnt)
   {
      iptr=*pointer++;
      if (iptr->flag != OBJ_GRP)
      {
         fprintf(out_fp,
         "%lu\t%lu\t%.0f\t%lu\t%s\n",
            iptr->count,iptr->files,iptr->xfer/1024,
            iptr->visit,iptr->string);
      }
      cnt--;
   }
   fclose(out_fp);
   return;
}

/*********************************************/
/* DUMP_ALL_SEARCH - dump search htab file   */
/*********************************************/

void dump_all_search()
{
   SNODEPTR sptr, *pointer;
   FILE     *out_fp;
   char     filename[256];
   u_char   cnt=a_ctr;

   /* generate file name */
   snprintf(filename, sizeof(filename),"%s/search_%04d%02d.%s",
      (dump_path)?dump_path:".",cur_year,cur_month,dump_ext);

   /* open file */
   if ( (out_fp=open_out_file(filename))==NULL ) return;

   /* need a header? */
   if (dump_header)
   {
      fprintf(out_fp,"%s\t%s\n",msg_h_hits,msg_h_search);
   }

   /* dump 'em */
   pointer=s_array;
   while(cnt)
   {
      sptr=*pointer++;
      fprintf(out_fp,"%lu\t%s\n",sptr->count,sptr->string);
      cnt--;
   }
   fclose(out_fp);
   return;
}

/*********************************************/
/* WRITE_MAIN_INDEX - main index.html file   */
/*********************************************/

int write_main_index()
{
   /* create main index file */

   int  i,days_in_month;
   int  lyear=0;
   int	s_mth=0;
   double  gt_hit=0.0;
   double  gt_files=0.0;
   double  gt_pages=0.0;
   double  gt_xfer=0.0;
   double  gt_visits=0.0;
   char    index_fname[256];
   char    buffer[BUFSIZE];

   if (verbose>1) printf("%s\n",msg_gen_sum);

   snprintf(buffer, sizeof(buffer),"%s %s",msg_main_us,hname);

   for (i=0;i<12;i++)                   /* get last month in history */
   {
      if (hist_year[i]>lyear)
       { lyear=hist_year[i]; s_mth=hist_month[i]; }
      if (hist_year[i]==lyear)
      {
         if (hist_month[i]>=s_mth)
            s_mth=hist_month[i];
      }
   }

   i=(s_mth==12)?1:s_mth+1;

   /* now do html stuff... */
   snprintf(index_fname, sizeof(index_fname),"index.%s",html_ext);

   if ( (out_fp=fopen(index_fname,"w")) == NULL)
   {
      if (verbose)
      fprintf(stderr,"%s %s!\n",msg_no_open,index_fname);
      return 1;
   }
   // write_html_head(msg_main_per, out_fp);
   /* year graph */
   fprintf(out_fp,"<IMG SRC=\"usage.png\" ALT=\"%s\" "    \
                  "HEIGHT=256 WIDTH=512><P>\n",buffer);
   /* month table */
   fprintf(out_fp,"<TABLE WIDTH=600 BORDER=2 CELLSPACING=1 CELLPADDING=1>\n");
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   fprintf(out_fp,"<TR><TH COLSPAN=11 BGCOLOR=\"%s\" ALIGN=center>",GREY);
   fprintf(out_fp,"%s</TH></TR>\n",msg_main_sum);
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   fprintf(out_fp,"<TR><TH ALIGN=left ROWSPAN=2 BGCOLOR=\"%s\">"          \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",GREY,msg_h_mth);
   fprintf(out_fp,"<TH ALIGN=center COLSPAN=4 BGCOLOR=\"%s\">"            \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",GREY,msg_main_da);
   fprintf(out_fp,"<TH ALIGN=center COLSPAN=6 BGCOLOR=\"%s\">"            \
          "<FONT SIZE=\"-1\">%s</FONT></TH></TR>\n",GREY,msg_main_mt);
   fprintf(out_fp,"<TR><TH ALIGN=center BGCOLOR=\"%s\">"                  \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",DKGREEN,msg_h_hits);
   fprintf(out_fp,"<TH ALIGN=center BGCOLOR=\"%s\">"                      \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",LTBLUE,msg_h_files);
   fprintf(out_fp,"<TH ALIGN=center BGCOLOR=\"%s\">"                      \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",CYAN,msg_h_pages);
   fprintf(out_fp,"<TH ALIGN=center BGCOLOR=\"%s\">"                      \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",YELLOW,msg_h_visits);
   fprintf(out_fp,"<TH ALIGN=center BGCOLOR=\"%s\">"                      \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",ORANGE,msg_h_sites);
   fprintf(out_fp,"<TH ALIGN=center BGCOLOR=\"%s\">"                      \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",RED,msg_h_xfer);
   fprintf(out_fp,"<TH ALIGN=center BGCOLOR=\"%s\">"                      \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",YELLOW,msg_h_visits);
   fprintf(out_fp,"<TH ALIGN=center BGCOLOR=\"%s\">"                      \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",CYAN,msg_h_pages);
   fprintf(out_fp,"<TH ALIGN=center BGCOLOR=\"%s\">"                      \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",LTBLUE,msg_h_files);
   fprintf(out_fp,"<TH ALIGN=center BGCOLOR=\"%s\">"                      \
          "<FONT SIZE=\"-1\">%s</FONT></TH></TR>\n",DKGREEN,msg_h_hits);
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   for (i=0;i<12;i++)
   {
      if (--s_mth < 0) s_mth = 11;
      if ((hist_month[s_mth]==0) && (hist_files[s_mth]==0)) continue;
      days_in_month=(hist_lday[s_mth]-hist_fday[s_mth])+1;
      fprintf(out_fp,"<TR><TD NOWRAP><A HREF=\"usage_%04d%02d.%s\">"      \
                     "<FONT SIZE=\"-1\">%s %d</FONT></A></TD>\n",
                      hist_year[s_mth], hist_month[s_mth], html_ext,
                      s_month[hist_month[s_mth]-1], hist_year[s_mth]);
      fprintf(out_fp,"<TD ALIGN=right><FONT SIZE=\"-1\">%lu</FONT></TD>\n",
                      hist_hit[s_mth]/days_in_month);
      fprintf(out_fp,"<TD ALIGN=right><FONT SIZE=\"-1\">%lu</FONT></TD>\n",
                      hist_files[s_mth]/days_in_month);
      fprintf(out_fp,"<TD ALIGN=right><FONT SIZE=\"-1\">%lu</FONT></TD>\n",
                      hist_page[s_mth]/days_in_month);
      fprintf(out_fp,"<TD ALIGN=right><FONT SIZE=\"-1\">%lu</FONT></TD>\n",
                      hist_visit[s_mth]/days_in_month);
      fprintf(out_fp,"<TD ALIGN=right><FONT SIZE=\"-1\">%lu</FONT></TD>\n",
                      hist_site[s_mth]);
      fprintf(out_fp,"<TD ALIGN=right><FONT SIZE=\"-1\">%.0f</FONT></TD>\n",
                      hist_xfer[s_mth]);
      fprintf(out_fp,"<TD ALIGN=right><FONT SIZE=\"-1\">%lu</FONT></TD>\n",
                      hist_visit[s_mth]);
      fprintf(out_fp,"<TD ALIGN=right><FONT SIZE=\"-1\">%lu</FONT></TD>\n",
                      hist_page[s_mth]);
      fprintf(out_fp,"<TD ALIGN=right><FONT SIZE=\"-1\">%lu</FONT></TD>\n",
                      hist_files[s_mth]);
      fprintf(out_fp,"<TD ALIGN=right><FONT SIZE=\"-1\">%lu</FONT></TD></TR>\n",
                      hist_hit[s_mth]);
      gt_hit   += hist_hit[s_mth];
      gt_files += hist_files[s_mth];
      gt_pages += hist_page[s_mth];
      gt_xfer  += hist_xfer[s_mth];
      gt_visits+= hist_visit[s_mth];
   }
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   fprintf(out_fp,"<TR><TH BGCOLOR=\"%s\" COLSPAN=6 ALIGN=left>"          \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",GREY,msg_h_totals);
   fprintf(out_fp,"<TH BGCOLOR=\"%s\" ALIGN=right>"                       \
          "<FONT SIZE=\"-1\">%.0f</FONT></TH>\n",GREY,gt_xfer);
   fprintf(out_fp,"<TH BGCOLOR=\"%s\" ALIGN=right>"                       \
          "<FONT SIZE=\"-1\">%.0f</FONT></TH>\n",GREY,gt_visits);
   fprintf(out_fp,"<TH BGCOLOR=\"%s\" ALIGN=right>"                       \
          "<FONT SIZE=\"-1\">%.0f</FONT></TH>\n",GREY,gt_pages);
   fprintf(out_fp,"<TH BGCOLOR=\"%s\" ALIGN=right>"                       \
          "<FONT SIZE=\"-1\">%.0f</FONT></TH>\n",GREY,gt_files);
   fprintf(out_fp,"<TH BGCOLOR=\"%s\" ALIGN=right>"                       \
          "<FONT SIZE=\"-1\">%.0f</FONT></TH></TR>\n",GREY,gt_hit);
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   fprintf(out_fp,"</TABLE>\n");
   // write_html_tail(out_fp);
   fclose(out_fp);
   return 0;
}

/* Replacement for write_main_index */
int write_main_xml()
{
   /* create main index file */

   int  i,days_in_month;
   int  lyear=0;
   int	s_mth=0;
   double  gt_hit=0.0;
   double  gt_files=0.0;
   double  gt_pages=0.0;
   double  gt_xfer=0.0;
   double  gt_visits=0.0;
   char    xml_index_fname[256];
   char    buffer[BUFSIZE];

   if (verbose>1) printf("%s\n",msg_gen_sum);

   snprintf(buffer, sizeof(buffer),"%s %s",msg_main_us,hname);

   for (i=0;i<12;i++)                   /* get last month in history */
   {
      if (hist_year[i]>lyear)
       { lyear=hist_year[i]; s_mth=hist_month[i]; }
      if (hist_year[i]==lyear)
      {
         if (hist_month[i]>=s_mth)
            s_mth=hist_month[i];
      }
   }

   i=(s_mth==12)?1:s_mth+1;

   
   //year_graph6x(   "usage.png",         /* filename          */
    //               buffer,              /* graph title       */
     //              i,                   /* last month        */
      //             hist_hit,            /* data set 1        */
       //            hist_files,          /* data set 2        */
        //           hist_site,           /* data set 3        */
         //          hist_xfer,           /* data set 4        */
          //         hist_page,           /* data set 5        */
           //        hist_visit);         /* data set 6        */
   

   /* now do html stuff... */
   snprintf(xml_index_fname, sizeof(xml_index_fname), "index.%s","xml");
   
   if ( (xml_fp=fopen(xml_index_fname,"w")) == NULL)
   {
      if (verbose)
      fprintf(stderr,"%s %s!\n",msg_no_open,xml_index_fname);
      return 1;
   }

   fprintf(xml_fp, "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n");
   fprintf(xml_fp, "<?xml-stylesheet type=\"text/xsl\" href=\"stats.xsl\" ?>\n");
   fprintf(xml_fp, "<stats sitename=\"%s\">\n", hname);
   fprintf(xml_fp, "\t<monthly>\n");

   //write_html_head(msg_main_per, out_fp);
   /* year graph */
   //fprintf(out_fp,"<IMG SRC=\"usage.png\" ALT=\"%s\" "    \
                  "HEIGHT=256 WIDTH=512><P>\n",buffer);
   /* month table */
   /* 
   fprintf(out_fp,"<TABLE WIDTH=600 BORDER=2 CELLSPACING=1 CELLPADDING=1>\n");
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   fprintf(out_fp,"<TR><TH COLSPAN=11 BGCOLOR=\"%s\" ALIGN=center>",GREY);
   fprintf(out_fp,"%s</TH></TR>\n",msg_main_sum);
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   fprintf(out_fp,"<TR><TH ALIGN=left ROWSPAN=2 BGCOLOR=\"%s\">"          \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",GREY,msg_h_mth);
   fprintf(out_fp,"<TH ALIGN=center COLSPAN=4 BGCOLOR=\"%s\">"            \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",GREY,msg_main_da);
   fprintf(out_fp,"<TH ALIGN=center COLSPAN=6 BGCOLOR=\"%s\">"            \
          "<FONT SIZE=\"-1\">%s</FONT></TH></TR>\n",GREY,msg_main_mt);
   fprintf(out_fp,"<TR><TH ALIGN=center BGCOLOR=\"%s\">"                  \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",DKGREEN,msg_h_hits);
   fprintf(out_fp,"<TH ALIGN=center BGCOLOR=\"%s\">"                      \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",LTBLUE,msg_h_files);
   fprintf(out_fp,"<TH ALIGN=center BGCOLOR=\"%s\">"                      \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",CYAN,msg_h_pages);
   fprintf(out_fp,"<TH ALIGN=center BGCOLOR=\"%s\">"                      \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",YELLOW,msg_h_visits);
   fprintf(out_fp,"<TH ALIGN=center BGCOLOR=\"%s\">"                      \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",ORANGE,msg_h_sites);
   fprintf(out_fp,"<TH ALIGN=center BGCOLOR=\"%s\">"                      \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",RED,msg_h_xfer);
   fprintf(out_fp,"<TH ALIGN=center BGCOLOR=\"%s\">"                      \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",YELLOW,msg_h_visits);
   fprintf(out_fp,"<TH ALIGN=center BGCOLOR=\"%s\">"                      \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",CYAN,msg_h_pages);
   fprintf(out_fp,"<TH ALIGN=center BGCOLOR=\"%s\">"                      \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",LTBLUE,msg_h_files);
   fprintf(out_fp,"<TH ALIGN=center BGCOLOR=\"%s\">"                      \
          "<FONT SIZE=\"-1\">%s</FONT></TH></TR>\n",DKGREEN,msg_h_hits);
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   */
   for (i=0;i<12;i++)
   {
      if (--s_mth < 0) s_mth = 11;
      if ((hist_month[s_mth]==0) && (hist_files[s_mth]==0)) continue;
      days_in_month=(hist_lday[s_mth]-hist_fday[s_mth])+1;
	fprintf(xml_fp,"\t\t<month id=\"%04d%02d\" name=\"%s %d\">\n",hist_year[s_mth], hist_month[s_mth], s_month[hist_month[s_mth]-1], hist_year[s_mth]);
      /* 
       month name 
      fprintf(out_fp,"<TR><TD NOWRAP><A HREF=\"usage_%04d%02d.%s\">"      \
                     "<FONT SIZE=\"-1\">%s %d</FONT></A></TD>\n",
                      hist_year[s_mth], hist_month[s_mth], html_ext,
                      s_month[hist_month[s_mth]-1], hist_year[s_mth]);
       daily avg hits 
      fprintf(out_fp,"<TD ALIGN=right><FONT SIZE=\"-1\">%lu</FONT></TD>\n",
                      hist_hit[s_mth]/days_in_month);
       avg files 
      fprintf(out_fp,"<TD ALIGN=right><FONT SIZE=\"-1\">%lu</FONT></TD>\n",
                      hist_files[s_mth]/days_in_month);
      fprintf(out_fp,"<TD ALIGN=right><FONT SIZE=\"-1\">%lu</FONT></TD>\n",
                      hist_page[s_mth]/days_in_month);
      fprintf(out_fp,"<TD ALIGN=right><FONT SIZE=\"-1\">%lu</FONT></TD>\n",
                      hist_visit[s_mth]/days_in_month);
      fprintf(out_fp,"<TD ALIGN=right><FONT SIZE=\"-1\">%lu</FONT></TD>\n",
                      hist_site[s_mth]);
      fprintf(out_fp,"<TD ALIGN=right><FONT SIZE=\"-1\">%.0f</FONT></TD>\n",
                      hist_xfer[s_mth]);
      fprintf(out_fp,"<TD ALIGN=right><FONT SIZE=\"-1\">%lu</FONT></TD>\n",
                      hist_visit[s_mth]);
      fprintf(out_fp,"<TD ALIGN=right><FONT SIZE=\"-1\">%lu</FONT></TD>\n",
                      hist_page[s_mth]);
      fprintf(out_fp,"<TD ALIGN=right><FONT SIZE=\"-1\">%lu</FONT></TD>\n",
                      hist_files[s_mth]);
      fprintf(out_fp,"<TD ALIGN=right><FONT SIZE=\"-1\">%lu</FONT></TD></TR>\n",
                      hist_hit[s_mth]); */
      //fprintf(xml_fp,"<set label=\"%s %d\" value=\"%lu\" />\n", s_month[hist_month[s_mth]-1], hist_year[s_mth], hist_hit[s_mth]);
      /* daily avg */
      fprintf(xml_fp,"\t\t\t<hits sum=\"%lu\" avg=\"%lu\" />\n", hist_hit[s_mth], hist_hit[s_mth]/days_in_month);
      fprintf(xml_fp,"\t\t\t<files sum=\"%lu\" avg=\"%lu\" />\n", hist_files[s_mth], hist_files[s_mth]/days_in_month);
      fprintf(xml_fp,"\t\t\t<pages sum=\"%lu\" avg=\"%lu\" />\n", hist_page[s_mth], hist_page[s_mth]/days_in_month);
      fprintf(xml_fp,"\t\t\t<visits sum=\"%lu\" avg=\"%lu\" />\n", hist_visit[s_mth], hist_visit[s_mth]/days_in_month);
      fprintf(xml_fp,"\t\t\t<transfered sum=\"%.0f\" avg=\"%.0f\" />\n", hist_xfer[s_mth], hist_xfer[s_mth]/days_in_month);
      fprintf(xml_fp,"\t\t\t<sites sum=\"%lu\" avg=\"%lu\" />\n", hist_site[s_mth], hist_site[s_mth]/days_in_month);

      fprintf(xml_fp,"\t\t</month>\n");
      gt_hit   += hist_hit[s_mth];
      gt_files += hist_files[s_mth];
      gt_pages += hist_page[s_mth];
      gt_xfer  += hist_xfer[s_mth];
      gt_visits+= hist_visit[s_mth];
   }
   fprintf(xml_fp,"\t\t<totals hits=\"%.0f\" files=\"%.0f\" pages=\"%.0f\" transfered=\"%0.f\" visits=\"%0.f\" />\n", gt_hit, gt_files, gt_pages, gt_xfer, gt_visits);
   fprintf(xml_fp,"\t</monthly>\n");
   /* 
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   fprintf(out_fp,"<TR><TH BGCOLOR=\"%s\" COLSPAN=6 ALIGN=left>"          \
          "<FONT SIZE=\"-1\">%s</FONT></TH>\n",GREY,msg_h_totals);
   fprintf(out_fp,"<TH BGCOLOR=\"%s\" ALIGN=right>"                       \
          "<FONT SIZE=\"-1\">%.0f</FONT></TH>\n",GREY,gt_xfer);
   fprintf(out_fp,"<TH BGCOLOR=\"%s\" ALIGN=right>"                       \
          "<FONT SIZE=\"-1\">%.0f</FONT></TH>\n",GREY,gt_visits);
   fprintf(out_fp,"<TH BGCOLOR=\"%s\" ALIGN=right>"                       \
          "<FONT SIZE=\"-1\">%.0f</FONT></TH>\n",GREY,gt_pages);
   fprintf(out_fp,"<TH BGCOLOR=\"%s\" ALIGN=right>"                       \
          "<FONT SIZE=\"-1\">%.0f</FONT></TH>\n",GREY,gt_files);
   fprintf(out_fp,"<TH BGCOLOR=\"%s\" ALIGN=right>"                       \
          "<FONT SIZE=\"-1\">%.0f</FONT></TH></TR>\n",GREY,gt_hit);
   fprintf(out_fp,"<TR><TH HEIGHT=4></TH></TR>\n");
   fprintf(out_fp,"</TABLE>\n");
   write_html_tail(out_fp);
   fclose(out_fp); */
   fprintf(xml_fp,"</stats>\n");
   fclose(xml_fp);
   return 0;
}

/*********************************************/
/* QS_SITE_CMPH - QSort compare site by hits */
/*********************************************/

int qs_site_cmph(const void *cp1, const void *cp2)
{
   u_long  t1, t2;
   t1=(*(HNODEPTR *)cp1)->count;
   t2=(*(HNODEPTR *)cp2)->count;
   if (t1!=t2) return (t2<t1)?-1:1;
   /* if hits are the same, we sort by hostname instead */
   return strcmp( (*(HNODEPTR *)cp1)->string,
                  (*(HNODEPTR *)cp2)->string );
}

/*********************************************/
/* QS_SITE_CMPK - QSort cmp site by bytes    */
/*********************************************/

int qs_site_cmpk(const void *cp1, const void *cp2)
{
   double t1, t2;
   t1=(*(HNODEPTR *)cp1)->xfer;
   t2=(*(HNODEPTR *)cp2)->xfer;
   if (t1!=t2) return (t2<t1)?-1:1;
   /* if xfer bytes are the same, we sort by hostname instead */
   return strcmp( (*(HNODEPTR *)cp1)->string,
                  (*(HNODEPTR *)cp2)->string );
}

/*********************************************/
/* QS_URL_CMPH - QSort compare URL by hits   */
/*********************************************/

int qs_url_cmph(const void *cp1, const void *cp2)
{
   u_long  t1, t2;
   t1=(*(UNODEPTR *)cp1)->count;
   t2=(*(UNODEPTR *)cp2)->count;
   if (t1!=t2) return (t2<t1)?-1:1;
   /* if hits are the same, we sort by url instead */
   return strcmp( (*(UNODEPTR *)cp1)->string,
                  (*(UNODEPTR *)cp2)->string );
}

/*********************************************/
/* QS_URL_CMPK - QSort compare URL by bytes  */
/*********************************************/

int qs_url_cmpk(const void *cp1, const void *cp2)
{
   double t1, t2;
   t1=(*(UNODEPTR *)cp1)->xfer;
   t2=(*(UNODEPTR *)cp2)->xfer;
   if (t1!=t2) return (t2<t1)?-1:1;
   /* if xfer bytes are the same, we sort by url instead */
   return strcmp( (*(UNODEPTR *)cp1)->string,
                  (*(UNODEPTR *)cp2)->string );
}

/*********************************************/
/* QS_URL_CMPN - QSort compare URL by entry  */
/*********************************************/

int qs_url_cmpn(const void *cp1, const void *cp2)
{
   double t1, t2;
   t1=(*(UNODEPTR *)cp1)->entry;
   t2=(*(UNODEPTR *)cp2)->entry;
   if (t1!=t2) return (t2<t1)?-1:1;
   /* if xfer bytes are the same, we sort by url instead */
   return strcmp( (*(UNODEPTR *)cp1)->string,
                  (*(UNODEPTR *)cp2)->string );
}

/*********************************************/
/* QS_URL_CMPX - QSort compare URL by exit   */
/*********************************************/

int qs_url_cmpx(const void *cp1, const void *cp2)
{
   double t1, t2;
   t1=(*(UNODEPTR *)cp1)->exit;
   t2=(*(UNODEPTR *)cp2)->exit;
   if (t1!=t2) return (t2<t1)?-1:1;
   /* if xfer bytes are the same, we sort by url instead */
   return strcmp( (*(UNODEPTR *)cp1)->string,
                  (*(UNODEPTR *)cp2)->string );
}

/*********************************************/
/* QS_REF_CMPH - QSort compare Refs by hits  */
/*********************************************/

int qs_ref_cmph(const void *cp1, const void *cp2)
{
   u_long  t1, t2;
   t1=(*(RNODEPTR *)cp1)->count;
   t2=(*(RNODEPTR *)cp2)->count;
   if (t1!=t2) return (t2<t1)?-1:1;
   /* if hits are the same, we sort by referrer URL instead */
   return strcmp( (*(RNODEPTR *)cp1)->string,
                  (*(RNODEPTR *)cp2)->string );
}

/*********************************************/
/* QS_AGNT_CMPH - QSort cmp Agents by hits   */
/*********************************************/

int qs_agnt_cmph(const void *cp1, const void *cp2)
{
   u_long  t1, t2;
   t1=(*(ANODEPTR *)cp1)->count;
   t2=(*(ANODEPTR *)cp2)->count;
   if (t1!=t2) return (t2<t1)?-1:1;
   /* if hits are the same, we sort by agent string instead */
   return strcmp( (*(ANODEPTR *)cp1)->string,
                  (*(ANODEPTR *)cp2)->string );
}

/*********************************************/
/* QS_SRCH_CMPH - QSort cmp srch str by hits */
/*********************************************/

int qs_srch_cmph(const void *cp1, const void *cp2)
{
   u_long  t1, t2;
   t1=(*(SNODEPTR *)cp1)->count;
   t2=(*(SNODEPTR *)cp2)->count;
   if (t1!=t2) return (t2<t1)?-1:1;
   /* if hits are the same, we sort by search string instead */
   return strcmp( (*(SNODEPTR *)cp1)->string,
                  (*(SNODEPTR *)cp2)->string );
}

/*********************************************/
/* QS_IDENT_CMPH - QSort cmp ident by hits   */
/*********************************************/

int qs_ident_cmph(const void *cp1, const void *cp2)
{
   u_long  t1, t2;
   t1=(*(INODEPTR *)cp1)->count;
   t2=(*(INODEPTR *)cp2)->count;
   if (t1!=t2) return (t2<t1)?-1:1;
   /* if hits are the same, sort by ident (username) string instead */
   return strcmp( (*(INODEPTR *)cp1)->string,
                  (*(INODEPTR *)cp2)->string );
}

/*********************************************/
/* LOAD_SITE_ARRAY - load up the sort array  */
/*********************************************/

u_long load_site_array(HNODEPTR *pointer)
{
   HNODEPTR hptr;
   int      i;
   u_long   ctr = 0;

   /* load the array */
   for (i=0;i<MAXHASH;i++)
   {
      hptr=sm_htab[i];
      while (hptr!=NULL)
      {
         if (pointer==NULL) ctr++;       /* fancy way to just count 'em    */
         else *(pointer+ctr++)=hptr;     /* otherwise, really do the load  */
         hptr=hptr->next;
      }
   }
   return ctr;   /* return number loaded */
}

/*********************************************/
/* LOAD_URL_ARRAY - load up the sort array   */
/*********************************************/

u_long load_url_array(UNODEPTR *pointer)
{
   UNODEPTR uptr;
   int      i;
   u_long   ctr = 0;

   /* load the array */
   for (i=0;i<MAXHASH;i++)
   {
      uptr=um_htab[i];
      while (uptr!=NULL)
      {
         if (pointer==NULL) ctr++;       /* fancy way to just count 'em    */
         else *(pointer+ctr++)=uptr;     /* otherwise, really do the load  */
         uptr=uptr->next;
      }
   }
   return ctr;   /* return number loaded */
}

/*********************************************/
/* LOAD_REF_ARRAY - load up the sort array   */
/*********************************************/

u_long load_ref_array(RNODEPTR *pointer)
{
   RNODEPTR rptr;
   int      i;
   u_long   ctr = 0;

   /* load the array */
   for (i=0;i<MAXHASH;i++)
   {
      rptr=rm_htab[i];
      while (rptr!=NULL)
      {
         if (pointer==NULL) ctr++;       /* fancy way to just count 'em    */
         else *(pointer+ctr++)=rptr;     /* otherwise, really do the load  */
         rptr=rptr->next;
      }
   }
   return ctr;   /* return number loaded */
}

/*********************************************/
/* LOAD_AGENT_ARRAY - load up the sort array */
/*********************************************/

u_long load_agent_array(ANODEPTR *pointer)
{
   ANODEPTR aptr;
   int      i;
   u_long   ctr = 0;

   /* load the array */
   for (i=0;i<MAXHASH;i++)
   {
      aptr=am_htab[i];
      while (aptr!=NULL)
      {
         if (pointer==NULL) ctr++;       /* fancy way to just count 'em    */
         else *(pointer+ctr++)=aptr;     /* otherwise, really do the load  */
         aptr=aptr->next;
      }
   }
   return ctr;   /* return number loaded */
}

/*********************************************/
/* LOAD_SRCH_ARRAY - load up the sort array  */
/*********************************************/

u_long load_srch_array(SNODEPTR *pointer)
{
   SNODEPTR sptr;
   int      i;
   u_long   ctr = 0;

   /* load the array */
   for (i=0;i<MAXHASH;i++)
   {
      sptr=sr_htab[i];
      while (sptr!=NULL)
      {
         if (pointer==NULL) ctr++;       /* fancy way to just count 'em    */
         else *(pointer+ctr++)=sptr;     /* otherwise, really do the load  */
         sptr=sptr->next;
      }
   }
   return ctr;   /* return number loaded */
}

/*********************************************/
/* LOAD_IDENT_ARRAY - load up the sort array */
/*********************************************/

u_long load_ident_array(INODEPTR *pointer)
{
   INODEPTR iptr;
   int      i;
   u_long   ctr = 0;

   /* load the array */
   for (i=0;i<MAXHASH;i++)
   {
      iptr=im_htab[i];
      while (iptr!=NULL)
      {
         if (pointer==NULL) ctr++;       /* fancy way to just count 'em    */
         else *(pointer+ctr++)=iptr;     /* otherwise, really do the load  */
         iptr=iptr->next;
      }
   }
   return ctr;   /* return number loaded */
}

/*********************************************/
/* OPEN_OUT_FILE - Open file for output      */
/*********************************************/

FILE *open_out_file(char *filename)
{
   FILE *out_fp;

   /* open the file... */
   if ( (out_fp=fopen(filename,"w")) == NULL)
   {
      if (verbose)
      fprintf(stderr,"%s %s!\n",msg_no_open,filename);
      return NULL;
   }
   return out_fp;
}

