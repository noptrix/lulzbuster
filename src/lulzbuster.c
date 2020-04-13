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
* lulzbuster.c                                                                 *
*                                                                              *
* AUTHOR                                                                       *
* noptrix@nullsecurity.net                                                     *
*                                                                              *
*******************************************************************************/


/* sys includes */


/* own includes */
#include "lulzbuster.h"
#include "checks.h"
#include "help.h"
#include "error.h"
#include "opts.h"
#include "misc.h"
#include "http.h"
#include "attack.h"
#include "signals.h"


/* main program flow, driver and controller */
int main(int argc, char *argv[])
{
  opts_T *opts;

  /* prepare env shizzle */
  banner();
  check_argc(argc);
  opts = xcalloc(1, sizeof *opts);
  opts->curl = xcalloc(1, sizeof *opts->curl);
  set_default_opts(opts);
  parse_opts(argc, argv, opts);
  JSLOG("preparing env\n");
  check_opts(opts);
  check_args(opts);

  /* set extensions and attack urls */
  JSLOG("building attack urls\n");
  set_extensions(opts);
  set_attack_urls(opts);

  /* init curl stuff */
  if (init_http(opts->curl) == FALSE) {
    free_lulzbuster(opts);
    __EXIT_FAILURE;
  }

  /* tcp connection check before we continue */
  JSLOG("connection check\n");
  opts->wcard = check_conn_wildcard(opts->start_url);
  if (opts->wcard.conn_ok == FALSE) {
    ESLOG("could not connect to: %s\n", opts->start_url);
    free_lulzbuster(opts);
    __GAME_OVER;
    __EXIT_FAILURE;
  }
  JSLOG("connection ok\n");

  /* check for wildcard !HTTP-404 response */
  JSLOG("wildcard check\n");
  if (opts->wcard.resp_code == HTTP_OK) {
    WSLOG("wildcard response found for any resource request: HTTP %ld\n",
          opts->wcard.resp_code);
  } else {
    GSLOG("lulz! no wildcard detected\n");
  }

  /* set desired http options and show final options */
  if (set_http_options(opts) == FALSE) {
    free_lulzbuster(opts);
    __EXIT_FAILURE;
  }
  __PRINT_OPTS;

  /* real game */
  __GAME_START;
  launch_attack(opts);

  /* end game */
  free_lulzbuster(opts);
  __GAME_OVER;

  return 0;
}


/* default free() right before we exit. note: previous free()s in conjuction
 * with fatal errors (exit()s) otherwise double/multi frees would occur */
void free_lulzbuster(opts_T *opts)
{
  char **tptr = NULL;

  /* curl stuff here */
  cleanup_http(opts->curl);

  /* free attack_urls */
  if (opts->attack_urls != NULL) {
    for (tptr = opts->attack_urls; *tptr != NULL; ++tptr) {
      free(*tptr);
    }
  }
  free(opts->attack_urls);
  free(opts->extens);
  free(opts->http_ex_codes);
  free(opts->http_method);
  free(opts->curl);
  free(opts);

  return;
}


/* free() parsed_url members */
void free_parsed_url(url_T url)
{
  free(url.scheme);
  free(url.host);
  free(url.port);
  free(url.path);

  return;
}

