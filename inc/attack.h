/*******************************************************************************
*                ____                     _ __                                 *
*     ___  __ __/ / /__ ___ ______ ______(_) /___ __                           *
*    / _ \/ // / / (_-</ -_) __/ // / __/ / __/ // /                           *
*   /_//_/\_,_/_/_/___/\__/\__/\_,_/_/ /_/\__/\_, /                            *
*                                            /___/ team                        *
*                                                                              *
* lulzbuster                                                                   *
* A very fast and smart web directory and file enumeration tool written in C.  *
*                                                                              *
* FILE                                                                         *
* attack.h                                                                     *
*                                                                              *
* AUTHOR                                                                       *
* noptrix@nullsecurity.net                                                     *
*                                                                              *
*******************************************************************************/


#ifndef ATTACK_H
#define ATTACK_H


/*******************************************************************************
 * INCLUDES
 ******************************************************************************/


/* sys includes */


/* own includes */
#include "opts.h"
#include "http.h"


/*******************************************************************************
 * MACROS
 ******************************************************************************/


/* headline before formatstring. column widths + pipe positions are
 * tuned to line up exactly with the row formatter in emit_hit() /
 * log_hit() (see src/log.c). if you change CTYPE_COL_WIDTH or any
 * field width there, you MUST eyeball this header too. layout:
 *   code (4) | size  (5) | real size (9) | lines  (6) | words  (6) |
 *   content-type (20) | resp time (9) | url
 * pipes land at offsets matching the `[*] %-4ld | ... ` data rows */
#define HEADLINE \
  "code | size  | real size | lines  | words  | content-type         "  \
  "| resp time | url\n\n"

/* status line */
#define PERCENT (double) (my_jobno * 100) / (double) job->opts->num_attack_urls
#define __STATUS \
  CLOG(stderr, "\r%s%s[+]%s scanning %lu / %lu (%.2f%%)", CBOLD, CBLUE, \
       CRESET, my_jobno, job->opts->num_attack_urls, PERCENT)


/*******************************************************************************
 * VARS, EXT VARS, TYPEDEFS
 ******************************************************************************/


/* our attack job. logs[] is one open FILE* per selected format
 * (NULL when that format isn't enabled). __HIT iterates over the
 * non-NULL slots and emits a row in the matching format */
typedef struct {
  FILE *logs[LOG_FMT_COUNT];
  const char *url;
  opts_T *opts;
} job_T;


/*******************************************************************************
 * FUNCTION PROTOTYPES
 ******************************************************************************/


/* init and launch attack */
void launch_attack(opts_T *);


#endif

