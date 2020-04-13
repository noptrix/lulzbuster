/*******************************************************************************
*                ____                     _ __                                 *
*     ___  __ __/ / /__ ___ ______ ______(_) /___ __                           *
*    / _ \/ // / / (_-</ -_) __/ // / __/ / __/ // /                           *
*   /_//_/\_,_/_/_/___/\__/\__/\_,_/_/ /_/\__/\_, /                            *
*                                            /___/ team                        *
*                                                                              *
* lulzbuster                                                                   *
* A very fast and smart web-dir/file enumeration tool written in C.            *
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


/* headline before formatstring */
#define HEADLINE "code   size   real size   resp time   url\n\n"

/* formatstring for hit line */
#define HITFMT "%ld | %4.0lf%c | %8luB | %lfs | %s\n"

/* hit line */
#define __HIT(log) \
  CLOG(stderr, BGREEN"\r[*] "CRESET HITFMT, code, bytes, suf, real_size, rtime,\
       job->url); \
  if (log != stderr) {\
    CLOG(log, "[*] "HITFMT, code, bytes, suf, real_size, rtime, job->url); \
  }

/* status line */
#define PERCENT (double) (curjob * 100) / (double) job->opts->num_attack_urls
#define __STATUS \
  CLOG(stderr, "\r"BBLUE"[+]"CRESET" scanning %lu / %lu (%.2f%%)", curjob, \
       job->opts->num_attack_urls, PERCENT)


/*******************************************************************************
 * VARS, EXT VARS, TYPEDEFS
 ******************************************************************************/


/* our attack job */
typedef struct {
  FILE *logfile;
  const char *url;
  CURL *eh;
  opts_T *opts;
} job_T;


/*******************************************************************************
 * FUNCTION PROTOTYPES
 ******************************************************************************/


/* init and launch attack */
void launch_attack(opts_T *);


#endif

