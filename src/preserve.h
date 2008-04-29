#ifndef _PRESERVE_H
#define _PRESERVE_H

extern void    get_history();                 /* load history file        */
extern void    put_history();                 /* save history file        */
extern int     save_state();                  /* save run state           */
extern int     restore_state();               /* restore run state        */

extern int     hist_month[12];                /* arrays for monthly total */
extern int     hist_year[12];
extern u_long  hist_hit[12];                  /* calculations: used to    */
extern u_long  hist_files[12];                /* produce index.html       */
extern u_long  hist_site[12];                 /* these are read and saved */
extern double  hist_xfer[12];                 /* in the history file      */
extern u_long  hist_page[12];
extern u_long  hist_visit[12];

extern int     hist_fday[12];                 /* first/last day arrays    */
extern int     hist_lday[12];

#endif  /* _PRESERVE_H */
