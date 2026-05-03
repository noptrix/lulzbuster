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
* signals.h                                                                    *
*                                                                              *
* AUTHOR                                                                       *
* noptrix@nullsecurity.net                                                     *
*                                                                              *
*******************************************************************************/


#ifndef SIGNALS_H
#define SIGNALS_H


/*******************************************************************************
 * INCLUDES
 ******************************************************************************/


/* sys includes */
#include <signal.h>


/* own includes */


/*******************************************************************************
 * MACROS
 ******************************************************************************/


/*******************************************************************************
 * TYPEDEFS
 ******************************************************************************/


/* for signal handlers */
typedef void sigfunc(int);


/*******************************************************************************
 * VARS
 ******************************************************************************/


/* set by sig_int, polled by attack() workers and the curl progress
 * callback so a ctrl+c bails the scan gracefully (instead of _exit).
 * sig_atomic_t + volatile = the only things you can write from a
 * signal handler portably */
extern volatile sig_atomic_t g_interrupted;


/*******************************************************************************
 * FUNCTION PROTOTYPES
 ******************************************************************************/


/* reliable version of signal() using POSIX sigaction
 * - ripped from Stevens (R.I.P.) */
sigfunc *xsignal(int, sigfunc *);

/* signal handlers */
void sig_int(int);
void sig_alrm(int);
void sig_usr1(int);
void sig_usr2(int);


#endif

