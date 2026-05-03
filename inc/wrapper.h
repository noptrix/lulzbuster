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
* wrapper.h                                                                    *
*                                                                              *
* AUTHOR                                                                       *
* noptrix@nullsecurity.net                                                     *
*                                                                              *
*******************************************************************************/


#ifndef WRAPPER_H
#define WRAPPER_H


/*******************************************************************************
 * INCLUDES
 ******************************************************************************/


/* sys includes */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>


/* own includes */


/*******************************************************************************
 * MACROS
 ******************************************************************************/


/* tri-state sentinel for the few check_*() funcs that need a third value
 * beyond bool true/false (e.g. user passed '?' to list available choices
 * and we should print + exit cleanly). those funcs return unsigned char,
 * everything else uses <stdbool.h> bool */
#define ASK   0x02

/* curl-style long flags - kept as longs because that's what curl_easy_setopt
 * wants for its boolean-ish options */
#define OFF   0L
#define ON    1L

/* exit() macros */
#define __EXIT_SUCCESS  exit(EXIT_SUCCESS)
#define __EXIT_FAILURE  exit(EXIT_FAILURE)

/* replace atoi() with strtol() */
#define ATOI(str) strtol(str, (char **) NULL, 10)

/* get array size */
#define ARRAY_SIZE(x) (sizeof((x)) / sizeof((x)[0]))


/*******************************************************************************
 * TYPEDEFS
 ******************************************************************************/


/* for signal handlers */
typedef void sigfunc(int);


/*******************************************************************************
 * VARS
 ******************************************************************************/


/*******************************************************************************
 * FUNCTION PROTOTYPES
 ******************************************************************************/


/* the declarations below this are only prototypes for our wrapper routines -
 * see the relevant manpages. don't bother me with this. */

/* memory */
sigfunc *xsignal(int, sigfunc *);
void *xrealloc(void *, size_t);
void *xcalloc(size_t, size_t);
void *xmalloc(size_t);
void *xmemset(void *, int, size_t);
void *xmemcpy(void *, const void *, size_t);

/* misc */
char *touplow(const char *, const char *);

#endif

