#ifndef _OUTPUT_H
#define _OUTPUT_H

extern int   write_main_index();                    /* produce main HTML   */
extern int   write_main_xml();		    			/* produce main XML Files */
extern int	 write_month_xml();						/* montly XML page */
extern FILE  *open_out_file(char *);                /* open output file    */

#endif  /* _OUTPUT_H */
