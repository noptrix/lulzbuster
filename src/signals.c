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
* signals.c                                                                    *
*                                                                              *
* AUTHOR                                                                       *
* noptrix@nullsecurity.net                                                     *
*                                                                              *
*******************************************************************************/


/* sys includes */
#include <stdio.h>


/* own includes */
#include "signals.h"


/* SIGINT handler */
void sig_int(int signo)
{
  (void) signo;

  /* reset */
  xsignal(SIGINT, sig_int);

  return;
}


/* SIGALRM handler */
void sig_alrm(int signo)
{
  (void) signo;

  /* reset */
  xsignal(SIGALRM, sig_int);

  return;
}


/* SIGUSR2 handler */
void sig_usr2(int signo)
{
  (void) signo;

  /* reset */
  xsignal(SIGUSR2, sig_int);

  return;
}


/* SIGUSR1 handler */
void sig_usr1(int signo)
{
  (void) signo;

  /* reset */
  xsignal(SIGUSR1, sig_int);

  return;
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

