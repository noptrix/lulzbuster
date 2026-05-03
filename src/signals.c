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
* signals.c                                                                    *
*                                                                              *
* AUTHOR                                                                       *
* noptrix@nullsecurity.net                                                     *
*                                                                              *
*******************************************************************************/


/* sys includes */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>


/* own includes */
#include "signals.h"


/* set by sig_int, polled by workers + main thread for graceful bail
 * and session save. sig_atomic_t = the only safe write from a signal
 * handler. defined here, declared extern in signals.h */
volatile sig_atomic_t g_interrupted = 0;


/* SIGINT handler. only async-signal-safe calls allowed here: write(2)
 * and a sig_atomic_t store. avoid stdio. workers check g_interrupted
 * to bail gracefully; main thread does the actual save+exit. on a 2nd
 * ctrl+c we bail hard via _exit (in case we're stuck somewhere) */
void sig_int(int signo)
{
  static const char msg[] =
    "\n\033[1;33;10m[!] \033[0minterrupted, finishing in-flight reqs...\n";
  static const char msg2[] =
    "\n\033[1;33;10m[!] \033[0msecond ctrl+c, bailing hard\n";

  (void) signo;
  if (g_interrupted == 0) {
    g_interrupted = 1;
    (void) !write(STDERR_FILENO, msg, sizeof(msg) - 1);
  } else {
    (void) !write(STDERR_FILENO, msg2, sizeof(msg2) - 1);
    _exit(EXIT_FAILURE);
  }
}


/* SIGALRM handler. armed by main() when -T was given; on fire we
 * piggyback on the SIGINT machinery (set g_interrupted, workers bail,
 * main saves the session). only async-signal-safe calls allowed */
void sig_alrm(int signo)
{
  static const char msg[] =
    "\n\033[1;33;10m[!] \033[0mglobal timeout reached, finishing in-flight "
    "reqs...\n";

  (void) signo;
  if (g_interrupted == 0) {
    g_interrupted = 1;
    (void) !write(STDERR_FILENO, msg, sizeof(msg) - 1);
  }
}


/* SIGUSR2 handler - scaffolding for future session save/restore */
void sig_usr2(int signo)
{
  (void) signo;
}


/* SIGUSR1 handler - scaffolding for future session save/restore */
void sig_usr1(int signo)
{
  (void) signo;
}


/* reliable version of signal() using POSIX sigaction
 * - ripped from Stevens (R.I.P.) */
sigfunc *xsignal(int signo, sigfunc *func)
{
  struct sigaction act, oact;

  act.sa_handler = func;
  sigemptyset(&act.sa_mask);
  act.sa_flags = 0;

  if (signo == SIGALRM) {
#ifdef  SA_INTERRUPT
    act.sa_flags |= SA_INTERRUPT;
#endif
  } else {
    act.sa_flags |= SA_RESTART;
  }

  if (sigaction(signo, &act, &oact) < 0) {
    return SIG_ERR;
  }

  return oact.sa_handler;
}

