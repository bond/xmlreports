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
#include "parser.h"

/* internal function prototypes */
void fmt_logrec(char *);
int  parse_record_web(char *);
int  parse_record_ftp(char *);
int  parse_record_squid(char *);

/*********************************************/
/* FMT_LOGREC - terminate log fields w/zeros */
/*********************************************/

void fmt_logrec(char *buffer)
{
   char *cp=buffer;
   int  q=0,b=0,p=0;

   while (*cp != '\0')
   {
      /* break record up, terminate fields with '\0' */
      switch (*cp)
      {
       case ' ': if (b || q || p) break; *cp='\0'; break;
       case '"': q^=1;  break;
       case '[': if (q) break; b++; break;
       case ']': if (q) break; if (b>0) b--; break;
       case '(': if (q) break; p++; break;
       case ')': if (q) break; if (p>0) p--; break;
      }
      cp++;
   }
}

/*********************************************/
/* PARSE_RECORD - uhhh, you know...          */
/*********************************************/

int parse_record(char *buffer)
{
   /* clear out structure */
   memset(&log_rec,0,sizeof(struct log_struct));
/*
   log_rec.hostname[0]=0;
   log_rec.datetime[0]=0;
   log_rec.url[0]=0;
   log_rec.resp_code=0;
   log_rec.xfer_size=0;
   log_rec.refer[0]=0;
   log_rec.agent[0]=0;
   log_rec.srchstr[0]=0;
   log_rec.ident[0]=0;
*/
#ifdef USE_DNS
   memset(&log_rec.addr,0,sizeof(struct in_addr));
#endif

   /* call appropriate handler */
   switch (log_type)
   {
      default:
      case LOG_CLF:   return parse_record_web(buffer);   break; /* clf   */
      case LOG_FTP:   return parse_record_ftp(buffer);   break; /* ftp   */
      case LOG_SQUID: return parse_record_squid(buffer); break; /* squid */
   }
}

/*********************************************/
/* PARSE_RECORD_FTP - ftp log handler        */
/*********************************************/

int parse_record_ftp(char *buffer)
{
   int size;
   int i,j;
   char *cp1, *cp2, *cpx, *cpy, *eob;

   size = strlen(buffer);                 /* get length of buffer        */
   eob = buffer+size;                     /* calculate end of buffer     */
   fmt_logrec(buffer);                    /* seperate fields with \0's   */

   /* Start out with date/time       */
   cp1=buffer;
   while (*cp1!=0 && cp1<eob) cp1++;
   while (*cp1==0) cp1++;
   cpx=cp1;       /* save month name */
   while (*cp1!=0 && cp1<eob) cp1++;
   while (*cp1==0) cp1++;
   i=atoi(cp1);   /* get day number  */
   while (*cp1!=0 && cp1<eob) cp1++;
   while (*cp1==0) cp1++;
   cpy=cp1;       /* get timestamp   */
   while (*cp1!=0 && cp1<eob) cp1++;
   while (*cp1==0) cp1++;
   j=atoi(cp1);   /* get year        */

   /* minimal sanity check */
   if (*(cpy+2)!=':' || *(cpy+5)!=':') return 0;
   if (j<1990 || j>2100) return 0;
   if (i<1 || i>31) return 0;

   /* format date/time field         */
   snprintf(log_rec.datetime, sizeof(log_rec.datetime),"[%02d/%s/%4d:%s -0000]",i,cpx,j,cpy);

   /* skip seconds... */
   while (*cp1!=0 && cp1<eob) cp1++;
   while (*cp1==0) cp1++;
   while (*cp1!=0 && cp1<eob) cp1++;
   while (*cp1==0) cp1++;

   /* get hostname */
   cp2=log_rec.hostname;
   strncpy(cp2,cp1,MAXHOST-1);

   /* get filesize */
   while (*cp1!=0 && cp1<eob) cp1++;
   while (*cp1==0) cp1++;
   if (*cp1<'0'||*cp1>'9') log_rec.xfer_size=0;
   else log_rec.xfer_size = strtoul(cp1,NULL,10);

   /* URL stuff */
   while (*cp1!=0 && cp1<eob) cp1++;
   while (*cp1==0) cp1++;
   cpx=cp1;
   /* get next field for later */
   while (*cp1!=0 && cp1<eob) cp1++;
   while (*cp1==0) cp1++;
   if (strlen(cpx)>MAXURL-20) *(cpx+(MAXURL-20))=0;

   /* skip next two */
   while (*cp1!=0 && cp1<eob) cp1++;
   while (*cp1==0) cp1++;
   while (*cp1!=0 && cp1<eob) cp1++;
   while (*cp1==0) cp1++;

   /* fabricate an appropriate request string based on direction */
   if (*cp1=='i') snprintf(log_rec.url, sizeof(log_rec.url),"\"POST %s HTTP/1.0\"",cpx);
      else        snprintf(log_rec.url, sizeof(log_rec.url),"\"GET %s HTTP/1.0\"",cpx);

   if (cp1<eob) cp1++;
   if (cp1<eob) cp1++;
   while (*cp1!=0 && cp1<eob) cp1++;
   if (cp1<eob) cp1++;
   cp2=log_rec.ident;
   while (*cp1!=0 && cp1<eob) *cp2++ = *cp1++;
   *cp2='\0';

   /* return appropriate response code */
   log_rec.resp_code=(*(eob-2)=='i')?206:200;

   return 1;
}

/*********************************************/
/* PARSE_RECORD_WEB - web log handler        */
/*********************************************/

int parse_record_web(char *buffer)
{
   int size;
   char *cp1, *cp2, *cpx, *eob, *eos;

   size = strlen(buffer);                 /* get length of buffer        */
   eob = buffer+size;                     /* calculate end of buffer     */
   fmt_logrec(buffer);                    /* seperate fields with \0's   */

   /* HOSTNAME */
   cp1 = cpx = buffer; cp2=log_rec.hostname;
   eos = (cp1+MAXHOST)-1;
   if (eos >= eob) eos=eob-1;

   while ( (*cp1 != '\0') && (cp1 != eos) ) *cp2++ = *cp1++;
   *cp2 = '\0';
   if (*cp1 != '\0')
   {
      if (verbose)
      {
         fprintf(stderr,"%s",msg_big_host);
         if (debug_mode) fprintf(stderr,": %s\n",cpx);
         else fprintf(stderr,"\n");
      }
      while (*cp1 != '\0') cp1++;
   }
   if (cp1 < eob) cp1++;

   /* skip next field (ident) */
   while ( (*cp1 != '\0') && (cp1 < eob) ) cp1++;
   if (cp1 < eob) cp1++;

   /* IDENT (authuser) field */
   cpx = cp1;
   cp2 = log_rec.ident;
   eos = (cp1+MAXIDENT-1);
   if (eos >= eob) eos=eob-1;

   while ( (*cp1 != '[') && (cp1 < eos) ) /* remove embeded spaces */
   {
      if (*cp1=='\0') *cp1=' ';
      *cp2++=*cp1++;
   }
   *cp2--='\0';

   if (cp1 >= eob) return 0;

   /* check if oversized username */
   if (*cp1 != '[')
   {
      if (verbose)
      {
         fprintf(stderr,"%s",msg_big_user);
         if (debug_mode) fprintf(stderr,": %s\n",cpx);
         else fprintf(stderr,"\n");
      }
      while ( (*cp1 != '[') && (cp1 < eob) ) cp1++;
   }

   /* strip trailing space(s) */
   while (*cp2==' ') *cp2--='\0';

   /* date/time string */
   cpx = cp1;
   cp2 = log_rec.datetime;
   eos = (cp1+28);
   if (eos >= eob) eos=eob-1;

   while ( (*cp1 != '\0') && (cp1 != eos) ) *cp2++ = *cp1++;
   *cp2 = '\0';
   if (*cp1 != '\0')
   {
      if (verbose)
      {
         fprintf(stderr,"%s",msg_big_date);
         if (debug_mode) fprintf(stderr,": %s\n",cpx);
         else fprintf(stderr,"\n");
      }
      while (*cp1 != '\0') cp1++;
   }
   if (cp1 < eob) cp1++;

   /* minimal sanity check on timestamp */
   if ( (log_rec.datetime[0] != '[') ||
        (log_rec.datetime[3] != '/') ||
        (cp1 >= eob))  return 0;

   /* HTTP request */
   cpx = cp1;
   cp2 = log_rec.url;
   eos = (cp1+MAXURL-1);
   if (eos >= eob) eos = eob-1;

   while ( (*cp1 != '\0') && (cp1 != eos) ) *cp2++ = *cp1++;
   *cp2 = '\0';
   if (*cp1 != '\0')
   {
      if (verbose)
      {
         fprintf(stderr,"%s",msg_big_req);
         if (debug_mode) fprintf(stderr,": %s\n",cpx);
         else fprintf(stderr,"\n");
      }
      while (*cp1 != '\0') cp1++;
   }
   if (cp1 < eob) cp1++;

   if ( (log_rec.url[0] != '"') ||
        (cp1 >= eob) ) return 0;

   /* response code */
   log_rec.resp_code = atoi(cp1);

   /* xfer size */
   while ( (*cp1 != '\0') && (cp1 < eob) ) cp1++;
   if (cp1 < eob) cp1++;
   if (*cp1<'0'||*cp1>'9') log_rec.xfer_size=0;
   else log_rec.xfer_size = strtoul(cp1,NULL,10);

   /* done with CLF record */
   if (cp1>=eob) return 1;

   while ( (*cp1 != '\0') && (*cp1 != '\n') && (cp1 < eob) ) cp1++;
   if (cp1 < eob) cp1++;
   /* get referrer if present */
   cpx = cp1;
   cp2 = log_rec.refer;
   eos = (cp1+MAXREF-1);
   if (eos >= eob) eos = eob-1;

   while ( (*cp1 != '\0') && (*cp1 != '\n') && (cp1 != eos) ) *cp2++ = *cp1++;
   *cp2 = '\0';
   if (*cp1 != '\0')
   {
      if (verbose)
      {
         fprintf(stderr,"%s",msg_big_ref);
         if (debug_mode) fprintf(stderr,": %s\n",cpx);
         else fprintf(stderr,"\n");
      }
      while (*cp1 != '\0') cp1++;
   }
   if (cp1 < eob) cp1++;

   cpx = cp1;
   cp2 = log_rec.agent;
   eos = cp1+(MAXAGENT-1);
   if (eos >= eob) eos = eob-1;

   while ( (*cp1 != '\0') && (cp1 != eos) ) *cp2++ = *cp1++;
   *cp2 = '\0';

   return 1;     /* maybe a valid record, return with TRUE */
}

/*********************************************/
/* PARSE_RECORD_SQUID - squid log handler    */
/*********************************************/

int parse_record_squid(char *buffer)
{
   int size;
   time_t i;
   char *cp1, *cp2, *cpx, *eob, *eos;

   size = strlen(buffer);                 /* get length of buffer        */
   eob = buffer+size;                     /* calculate end of buffer     */
   fmt_logrec(buffer);                    /* seperate fields with \0's   */

   /* date/time */
   cp1=buffer;
   i=atoi(cp1);		/* get timestamp */

   /* format date/time field */
   strftime(log_rec.datetime,sizeof(log_rec.datetime),
            "[%d/%b/%Y:%H:%M:%S -0000]",localtime(&i));

   while (*cp1!=0 && cp1<eob) cp1++;
   while (*cp1==0) cp1++;

   /* skip request size */
   while (*cp1!=0 && cp1<eob) cp1++;
   while (*cp1==0) cp1++;

   /* HOSTNAME */
   cpx = cp1; cp2=log_rec.hostname;
   eos = (cp1+MAXHOST)-1;
   if (eos >= eob) eos=eob-1;

   while ((*cp1 != '\0') && (cp1 != eos)) *cp2++ = *cp1++;
   *cp2='\0';
   if (*cp1 != '\0')
   {
      if (verbose)
      {
         fprintf(stderr,"%s",msg_big_host);
         if (debug_mode) fprintf(stderr,": %s\n",cpx);
         else fprintf(stderr,"\n");
      }
      while (*cp1 != '\0') cp1++;
   }
   if (cp1 < eob) cp1++;

   /* skip cache status */
   while (*cp1!=0 && cp1<eob && *cp1!='/') cp1++;
   cp1++;

   /* response code */
   log_rec.resp_code = atoi(cp1);
   while (*cp1!=0 && cp1<eob) cp1++;
   while (*cp1==0) cp1++;

   /* xfer size */
   if (*cp1<'0'||*cp1>'9') log_rec.xfer_size=0;
   else log_rec.xfer_size = strtoul(cp1,NULL,10);

   while (*cp1!=0 && cp1<eob) cp1++;
   while (*cp1==0) cp1++;

   /* HTTP request type */
   cpx = cp1;
   cp2 = log_rec.url;
   *cp2++ = '\"';
   eos = (cp1+MAXURL-1);
   if (eos >= eob) eos = eob-1;

   while ( (*cp1 != '\0') && (cp1 != eos) ) *cp2++ = *cp1++;
   *cp2 = '\0';
   if (*cp1 != '\0')
   {
      if (verbose)
      {
         fprintf(stderr,"%s",msg_big_req);
         if (debug_mode) fprintf(stderr,": %s\n",cpx);
         else fprintf(stderr,"\n");
      }
      while (*cp1 != '\0') cp1++;
   }
   if (cp1 < eob) cp1++;

   *cp2++ = ' ';

   /* HTTP URL requested */
   cpx = cp1;
   eos = (cp1+MAXURL-1);
   if (eos >= eob) eos = eob-1;

   while ( (*cp1 != '\0') && (cp1 != eos) ) *cp2++ = *cp1++;
   *cp2 = '\0';
   if (*cp1 != '\0')
   {
      if (verbose)
      {
         fprintf(stderr,"%s",msg_big_req);
         if (debug_mode) fprintf(stderr,": %s\n",cpx);
         else fprintf(stderr,"\n");
      }
      while (*cp1 != '\0') cp1++;
   }
   if (cp1 < eob) cp1++;

   *cp2++ = '\"';

   /* IDENT (authuser) field */
   cpx = cp1;
   cp2 = log_rec.ident;
   eos = (cp1+MAXIDENT-1);
   if (eos >= eob) eos=eob-1;

   while (*cp1 == ' ') cp1++; /* skip white space */

   while ( (*cp1 != ' ' && *cp1!='\0') && (cp1 < eos) )  *cp2++=*cp1++;

   *cp2--='\0';

   if (cp1 >= eob) return 0;

   /* strip trailing space(s) */
   while (*cp2==' ') *cp2--='\0';

   /* we have no interest in the remaining fields */
   return 1;
}
