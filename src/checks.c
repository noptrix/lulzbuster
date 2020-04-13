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
* checks.c                                                                     *
*                                                                              *
* AUTHOR                                                                       *
* noptrix@nullsecurity.net                                                     *
*                                                                              *
*******************************************************************************/


/* sys includes */
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <unistd.h>


/* own includes */
#include "checks.h"
#include "lulzbuster.h"
#include "error.h"
#include "http.h"
#include "misc.h"


/* static func prototypes */
static unsigned char check_url(const char *);
static unsigned char check_http_method(char *);
static unsigned char check_file(const char *, int);
static unsigned char check_num(const unsigned short int,
                               const unsigned short int);
static unsigned char check_creds(const char *);
static unsigned char check_proxy(char *);
static unsigned char check_port(const char *);
static unsigned char check_http_version(const char *);


/* checks, if required arguments were selected */
void check_args(opts_T *opts)
{
  if (opts->start_url == NULL) {
    free_lulzbuster(opts);
    err(E_TARGET);
  }

  return;
}


/* check for argument count */
void check_argc(int argc)
{
  if (argc < 2) {
    err(E_ARGC);
  }

  return;
}


/* check URL format */
static unsigned char check_url(const char *target_url)
{
  register unsigned char check_ok = TRUE;
  char *scheme = NULL;
  CURLUcode rc = 0;
  CURLU *url = curl_url();

  rc = curl_url_set(url, CURLUPART_URL, target_url, 0);

  if (!rc) {
    rc = curl_url_get(url, CURLUPART_SCHEME, &scheme, 0);
    if (!rc) {
      if ((strcmp(scheme, "http") != 0) && (strcmp(scheme, "https") != 0)) {
        check_ok = FALSE;
      }
    }
  } else {
    check_ok = FALSE;
  }

  curl_free(scheme);
  curl_url_cleanup(url);

  return check_ok;
}


/* check HTTP request type */
static unsigned char check_http_method(char *http_method)
{
  register unsigned char check_ok = FALSE;
  register size_t j = 0, len = strlen(http_method) + 1;
  char *http_methods[] = {
    HTTP_HEAD, HTTP_GET, HTTP_POST, HTTP_PUT, HTTP_DELETE, HTTP_OPTIONS,
  };

  /* abort immediately bullshit long was given */
  if (len > MAX_METHOD_LEN) {
    return FALSE;
  }

  for (j = 0; j < ARRAY_SIZE(http_methods); j++) {
    if (http_method[0] == '?') {
      JSLOG("available HTTP requests types\n\n");
      for (j = 0; j < ARRAY_SIZE(http_methods); j++) {
        VSLOG(http_methods[j]);
        SLOG("\n");
      }
      SLOG("\n");
      check_ok = ASK;
      break;
    }
    if (!strcmp(http_method, http_methods[j])) {
      check_ok = TRUE;
      break;
    }
  }

  return check_ok;
}


/* check if we can open and read given file */
static unsigned char check_file(const char *file, int mode)
{
  register unsigned char check_ok = FALSE;
  FILE *fp = NULL;

  /* we need to create file if it does not exist before checking for W_OK bit */
  if (mode & (W_OK)) {
    fp = fopen(file, "a+");
    if (fp == NULL) {
      check_ok = FALSE;
    }
  }

  /* check for given mode */
  if (access(file, mode) == 0) {
    check_ok = TRUE;
  }

  /* delete file if created before because of W_OK bit */
  if (fp) {
    if (unlink(file) == -1) {
      err(W_UNLINK);
    }
    fclose(fp);
  }

  return check_ok;
}


/* check if num exceeds MAX_* / lowers MIN_* */
static unsigned char check_num(const unsigned short int num,
                               const unsigned short int val)
{
  register unsigned char check_ok = FALSE;

  switch (val) {
   case MAX_THRDS:
     check_ok = (num > MAX_THRDS) ? FALSE : TRUE;
     break;
   case MAX_DELAY: /* covers also conn and read timeout */
     check_ok = (num > MAX_DELAY) ? FALSE : TRUE;
     break;
   case MIN_GLOB_TIMEOUT:
     check_ok = (num != 0 && num < MIN_GLOB_TIMEOUT) ? FALSE : TRUE;
     break;
   case MAX_CONN_CACHE:
     check_ok = (num > MAX_CONN_CACHE) ? FALSE : TRUE;
     break;
   default:
     check_ok = TRUE;
  }

  return check_ok;
}


/* check if credentials format is correct */
static unsigned char check_creds(const char *str)
{
  register unsigned char check_ok = FALSE;

  if (str[0] && str[1]) {
    check_ok = TRUE;
  }

  return check_ok;
}


/* check if correct scheme and <num> parts were given for proxy */
static unsigned char check_proxy(char *str)
{
  register unsigned char check_ok = TRUE;
  register size_t i = 0, len = strlen(str) + 1;
  char tmpstr[len];
  char **pstr = NULL,
       *proxy_schemes[] = {
         PROXY_SCHEME_HTTP, PROXY_SCHEME_HTTPS, PROXY_SCHEME_SOCKS4,
         PROXY_SCHEME_SOCKS4A, PROXY_SCHEME_SOCKS5, PROXY_SCHEME_SOCKS5H
       };

  /* we don't want strtok() to fuck up our original string */
  strcpy(tmpstr, str);
  tmpstr[len - 1] = 0x00;

  pstr = parse_str_token(tmpstr, ":", 4);

  /* user asked for available proxy schemes */
  if (tmpstr[0] == '?') {
    free(pstr);
    JSLOG("available proxy schemes\n\n");
    for (i = 0; i < ARRAY_SIZE(proxy_schemes); ++i) {
      VSLOG(proxy_schemes[i]);
      SLOG("\n");
    }
    SLOG("\n");
    return ASK;
  }

  /* too short or too long */
  if (pstr[3] != NULL) {
    check_ok = FALSE;
  }

  /* wrong scheme */
  if ((strcmp(pstr[0], "http") != 0) && (strcmp(pstr[0], "https") != 0) &&
      (strcmp(pstr[0], "socks4") != 0) && (strcmp(pstr[0], "socks4a") != 0) &&
      (strcmp(pstr[0], "socks5") != 0) && (strcmp(pstr[0], "socks5h") != 0)) {
    check_ok = FALSE;
  }

  /* wrong port */
  if (pstr[2]) {
    if (!check_port(pstr[2]))
      check_ok = FALSE;
  } else {
    check_ok = FALSE;
  }

  free(pstr);

  return check_ok;
}


/* check if port is really between 0 and 65535 */
static unsigned char check_port(const char *port)
{
  register unsigned char check_ok = TRUE;
  long int p = 0;

  p = ATOI(port);

  /* note: 0 is inofficially ok but with lulzbuster does not make sense */
  if (p <= 0 || p > 65535) {
    check_ok = FALSE;
  }

  return check_ok;
}


/* check if a valid http version was specified */
static unsigned char check_http_version(const char *ver)
{
  register unsigned char check_ok = TRUE;
  char *http_vers[] = { HTTP_VER_10, HTTP_VER_11, HTTP_VER_20, HTTP_VER_30 };
  register size_t i = 0;

  if (ver[0] == '?') {
    JSLOG("available http versions\n\n");
    for (i = 0; i < ARRAY_SIZE(http_vers); ++i) {
      VSLOG(http_vers[i]);
      SLOG("\n");
    }
    SLOG("\n");
    return ASK;
  }

  for (i = 0; i < ARRAY_SIZE(http_vers); ++i) {
    if ((strcmp(ver, HTTP_VER_10) != 0) && (strcmp(ver, HTTP_VER_11) != 0) &&
        (strcmp(ver, HTTP_VER_20) != 0) && (strcmp(ver, HTTP_VER_30) != 0)) {
      check_ok = FALSE;
    }
  }

  return check_ok;
}


/* perform basic checks on all cmdline opts */
void check_opts(opts_T *opts)
{
  register unsigned char check_ok = FALSE;

  /* check if a correct/full HTTP url was given for target start url */
  if (!check_url(opts->start_url)) {
    free_lulzbuster(opts);
    err(E_URL);
  }

  /* check if correct http method was given */
  check_ok = check_http_method(opts->http_method);
  if (!check_ok) {
    free_lulzbuster(opts);
    err(E_METH);
  }
  if (check_ok == ASK) {
    free_lulzbuster(opts);
    __GAME_OVER;
    __EXIT_SUCCESS;
  }

  /* check proxy addr was supplied correctly. */
  if (opts->proxy) {
    check_ok = check_proxy(opts->proxy);
    if (!check_ok) {
      free_lulzbuster(opts);
      err(E_PROXY_ADDR);
    }
    if (check_ok == ASK) {
      free_lulzbuster(opts);
      __GAME_OVER;
      __EXIT_SUCCESS;
    }
  }

  /* check if user:pass was exactly supplied */
  if (opts->creds) {
    if (!check_creds(opts->creds)) {
      free_lulzbuster(opts);
      err(E_CREDS);
    }
  }

  /* check if user:pass (proxy) was exactly supplied */
  if (opts->proxy_creds) {
    if (!check_creds(opts->proxy_creds)) {
      free_lulzbuster(opts);
      err(E_PCREDS);
    }
  }

  /* check if valid http version was selected */
  if (opts->http_version) {
    check_ok = check_http_version(opts->http_version);
    if (!check_ok) {
      free_lulzbuster(opts);
      err(E_HTTP_VER);
    }
    if (check_ok == ASK) {
      free_lulzbuster(opts);
      __GAME_OVER;
      __EXIT_SUCCESS;
    }
  }

  /* check max threads value */
  if (!check_num(opts->threads, MAX_THRDS)) {
    err(W_THRDS);
  }

  /* check max connection cache size value */
  if (!check_num(opts->conn_cache, MAX_CONN_CACHE)) {
    err(W_MAXCONN_CACHE);
  }

  /* check max request delay, connect and read timeout value */
  if (!check_num(opts->delay, MAX_DELAY)) {
    err(W_DELAY);
  }

  /* check max global timeout value */
  if (!check_num(opts->glob_timeout, MIN_GLOB_TIMEOUT)) {
    err(W_GLOB_NUM);
  }

  /* check if we can read wordlist */
  if (!check_file(opts->wordlist, R_OK)) {
    free_lulzbuster(opts);
    err(E_RFILE);
  }

  /* check if we can write to logfile */
  if (opts->logfile) {
    if (!check_file(opts->logfile, W_OK)) {
      free_lulzbuster(opts);
      err(E_WFILE);
    }
  }

  return;
}

