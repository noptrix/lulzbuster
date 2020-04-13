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
* log.h                                                                        *
*                                                                              *
* AUTHOR                                                                       *
* noptrix@nullsecurity.net                                                     *
*                                                                              *
*******************************************************************************/


#ifndef LOG_H
#define LOG_H


/*******************************************************************************
 * INCLUDES
 ******************************************************************************/


/* sys includes */
#include <stdio.h>


/* own includes */


/*******************************************************************************
 * MACROS
 ******************************************************************************/


/* escape sequences */
#define CBLUE     "\033[1;34;10m"
#define CRED      "\033[1;31;10m"
#define CYELLOW   "\033[1;33;10m"
#define CGREEN    "\033[1;32;10m"
#define CBOLD     "\033[1;37;10m"
#define CRESET    "\033[0m"


/* shortenings for bold colors */
#define BBLUE     CBOLD CBLUE
#define BRED      CBOLD CRED
#define BYELLOW   CBOLD CYELLOW
#define BGREEN    CGREEN


/* message prefixes */
#define PJOB  "[+] "
#define PGOOD "[*] "
#define PVERB "    > "
#define PWARN "[!] "
#define PERR  "[-] "


/* simple one-format logging macros for colored output:
 * : stdout, S: stderr, C: custom */
#define LOG(...)          fprintf(stdout, __VA_ARGS__);
#define SLOG(...)         fprintf(stderr, __VA_ARGS__);
#define CLOG(file, ...)   fprintf(file, __VA_ARGS__);
#define JLOG(...)         fprintf(stdout, CBLUE PJOB CRESET __VA_ARGS__);
#define GLOG(...)         fprintf(stdout, CGREEN PGOOD CRESET __VA_ARGS__);
#define VLOG(...)         fprintf(stdout, PVERB __VA_ARGS__);
#define JSLOG(...)        fprintf(stderr, CBLUE PJOB CRESET __VA_ARGS__);
#define GSLOG(...)        fprintf(stderr, CGREEN PGOOD CRESET __VA_ARGS__);
#define VSLOG(...)        fprintf(stderr, PVERB "%s", __VA_ARGS__);
#define WSLOG(...)        fprintf(stderr, CYELLOW PWARN CRESET __VA_ARGS__);
#define ESLOG(...)        fprintf(stderr, CRED PERR CRESET __VA_ARGS__);


/* shorten 'game started' / 'game over' call */
#define __GAME_START  JSLOG("game started\n\n");
#define __GAME_OVER   JSLOG("game over\n");


/*******************************************************************************
 * VARS
 ******************************************************************************/


/*******************************************************************************
 * FUNCTION PROTOTYPES
 ******************************************************************************/


#endif

