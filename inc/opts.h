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
* opts.h                                                                       *
*                                                                              *
* AUTHOR                                                                       *
* noptrix@nullsecurity.net                                                     *
*                                                                              *
*******************************************************************************/


#ifndef OPTS_H
#define OPTS_H


/*******************************************************************************
 * INCLUDES
 ******************************************************************************/


/* sys includes */


/* own includes */
#include "wrapper.h"
#include "http.h"


/*******************************************************************************
 * MACROS
 ******************************************************************************/


/* default options */
#define DEF_HTTP_EX_CODES       "400,404,500,501,502,503"
#define DEF_HTTP_METHOD         "GET"
#define DEF_WORDLIST            "/usr/local/share/lulzbuster/lists/medium.txt"
#define DEF_USERAGENT           "Mozilla/5.0 (Windows NT 10.0; Win64; x64; " \
  "rv:72.0) Gecko/20100101 Firefox/72.0"
#define DEF_RAND_UA             OFF
#define DEF_AUTOREF_UPDATE      OFF
#define DEF_THREADS             30
#define DEF_CONN_CACHE          30
#define DEF_DELAY               OFF
#define DEF_CONN_TIMEOUT        10L
#define DEF_REQ_TIMEOUT         30L
#define DEF_GLOB_TIMEOUT        OFF
#define DEF_FOLLOW_REDIR_LEVEL  0
#define DEF_IN_SSL              OFF
#define DEF_NAMESERVER          "1.1.1.1,8.8.8.8,208.67.222.222"


/* max/min num values for errors and warnings */
#define MAX_THRDS         256
#define MAX_DELAY         60
#define MAX_CONN_TIMEOUT  60
#define MAX_REQ_TIMEOUT   60
#define MIN_GLOB_TIMEOUT  600
#define MAX_CONN_CACHE    100


/* print infos about final set options prior scan start - sorry, dirty */
#define FP  fprintf
#define EXCODES for (size_t i = 0; opts->http_ex_codes[i] != 0; i++) {\
  fprintf(stderr, "%ld ", opts->http_ex_codes[i]); }
#define EXTENS  for (char **tptr = opts->extens; *tptr != NULL; ++tptr) {\
  fprintf(stderr, "%s ", *tptr);\
}
#define __PRINT_OPTS  CLOG(stderr, "\n"); JSLOG("final settings\n\n"); \
  FP(stderr, "    > url:          %s", opts->start_url); CLOG(stderr, "\n"); \
  FP(stderr, "    > http method:  %s", opts->http_method); CLOG(stderr, "\n"); \
  FP(stderr, "    > http excodes: "); EXCODES; CLOG(stderr, "\n"); \
  FP(stderr, "    > follow redir: %u", opts->follow_redir); CLOG(stderr, "\n"); \
  if (opts->follow_redir == ON) {\
    FP(stderr, "    > redir level:  %ld", opts->follow_redir_level); \
    CLOG(stderr, "\n"); \
  }\
  if (opts->rand_ua != OFF) {\
    FP(stderr, "    > random ua:    %u", opts->rand_ua); CLOG(stderr, "\n"); \
  } else {\
    FP(stderr, "    > ua:           %s", opts->useragent); CLOG(stderr, "\n"); \
  }\
  if (opts->http_header) {\
    FP(stderr, "    > http header:  %s", opts->http_header); \
    CLOG(stderr, "\n"); \
  }\
  if (opts->creds) {\
    FP(stderr, "    > creds:        %s", opts->creds); CLOG(stderr, "\n"); \
  }\
  if (opts->http_version) {\
    FP(stderr, "    > http version: %s", \
       opts->http_version); CLOG(stderr, "\n"); \
  }\
  if (opts->delay != OFF) {\
    FP(stderr, "    > delay:        %us", opts->delay); CLOG(stderr, "\n"); \
  }\
  FP(stderr, "    > con timeout:  %lds", opts->conn_timeout); \
  CLOG(stderr, "\n"); \
  FP(stderr, "    > req timeout:  %lds", opts->req_timeout); \
  CLOG(stderr, "\n"); \
  if (opts->glob_timeout != OFF) {\
    FP(stderr, "    > glb timeout:  %us", opts->glob_timeout); \
    CLOG(stderr, "\n"); \
  }\
  FP(stderr, "    > threads:      %u", opts->threads); CLOG(stderr, "\n"); \
  FP(stderr, "    > con cache:    %ld", opts->conn_cache); CLOG(stderr, "\n"); \
  FP(stderr, "    > wordlist:     %s", opts->wordlist); CLOG(stderr, "\n"); \
  if (opts->extens && (strcmp(opts->extens[0], "") != 0)) {\
    FP(stderr, "    > extensions:   "); EXTENS; CLOG(stderr, "\n"); \
  }\
  if (opts->proxy) {\
    FP(stderr, "    > proxy:        %s", opts->proxy); CLOG(stderr, "\n"); \
  }\
  if (opts->proxy_creds) {\
    FP(stderr, "    > proxy creds:  %s", opts->proxy_creds); \
    CLOG(stderr, "\n"); \
  }\
  FP(stderr, "    > dns server:   %s", opts->nameserver); CLOG(stderr, "\n"); \
  if (opts->logfile) {\
    FP(stderr, "    > logfile:      %s", opts->logfile); CLOG(stderr, "\n"); \
  } else {\
    FP(stderr, "    > logfile:      stderr"); CLOG(stderr, "\n");\
  }\
  FP(stderr, "    > smart mode:   %u\n", opts->smart);\
  CLOG(stderr, "\n")


/* tcp connection timeout for our check_tcp_conn() */
#define TCP_CONN_TIMEOUT  5


/*******************************************************************************
 * VARS
 ******************************************************************************/


/* contains every options (cmdline, default, etc.) */
typedef struct {
  const char *start_url;            /* target start url (-u) */
  url_T parsed_url;                 /* parsed start_url */
  char **attack_urls;               /* dyn. built attack urls */
  unsigned long num_attack_urls;    /* num attack urls */
  char *http_method;                /* http request method (-h) */
  long int *http_ex_codes;          /* exclude http status codes (-x) */
  size_t num_http_ex_codes;         /* num excluded http status codes */
  unsigned char follow_redir;       /* follow redirect (-f) */
  long follow_redir_level;          /* max level to follow redirect (-i) */
  char *useragent;                  /* user-agent string (-U) */
  unsigned char rand_ua;            /* random user-agent (-G) */
  const char *http_header;          /* custom http header (-c) */
  const char *creds;                /* creds for http auth (-a) */
  unsigned char autoref;            /* auto update referrer (-r) */
  const char *http_version;         /* http version num (-j) */
  unsigned int delay;               /* num sec for requests delay (-D) */
  long conn_timeout;                /* num sec for connection timeout (-C) */
  long req_timeout;                 /* num sec for reqeuest timeout (-R) */
  unsigned short int glob_timeout;  /* num sec for global timeout (-T) */
  unsigned short int threads;       /* num threads (-t) */
  long conn_cache;                  /* num connection cache for curl (-g) */
  const char *wordlist;             /* wordlist file (-w) */
  char **extens;                    /* extension list (-E) */
  size_t num_extens;                /* num extensions */
  char *proxy;                      /* http proxy address (-p) */
  const char *proxy_creds;          /* creds for proxy auth (-P) */
  unsigned char in_ssl;             /* insecure ssl/tls mode (-i) */
  unsigned char smart;              /* anti-smart mode (-S) */
  const char *nameserver;           /* nameservers (-n) */
  const char *logfile;              /* logfile for found urls (-l) */
  wildcard_T wcard;                 /* wildcard table */
  curl_T *curl;                     /* pointer to curl table */
} opts_T;
  /*} __attribute__((packed)) opts_T;*/


/*******************************************************************************
 * FUNCTION PROTOTYPES
 ******************************************************************************/


/* set static http (curl) options */
unsigned char set_http_options(opts_T *);

/* set extensions and return num extensions */
void set_extensions(opts_T *);

/* set attack urls */
void set_attack_urls(opts_T *);

/* set default opts */
void set_default_opts(opts_T *);

/* parse cmdline opts */
void parse_opts(int, char **, opts_T *);


#endif

