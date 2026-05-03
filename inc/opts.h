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
#include <regex.h>


/* own includes */
#include "wrapper.h"
#include "http.h"
#include "log.h"


/*******************************************************************************
 * MACROS
 ******************************************************************************/


/* default options */
#define DEF_HTTP_EX_CODES       "400,404,500,501,502,503"
#define DEF_HTTP_METHOD         "GET"
#define DEF_WORDLIST            "/usr/local/share/lulzbuster/lists/medium.txt"
#define DEF_USERAGENT           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " \
  "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 " \
  "Edg/142.0.0.0"
#define DEF_RAND_UA             false
#define DEF_AUTOREF_UPDATE      false
#define DEF_THREADS             35
#define DEF_CONN_CACHE          35
#define DEF_DELAY               OFF
#define DEF_CONN_TIMEOUT        10L
#define DEF_REQ_TIMEOUT         30L
#define DEF_GLOB_TIMEOUT        OFF
#define DEF_FOLLOW_REDIR_LEVEL  -1L  /* curl: unlimited */
#define DEF_IN_SSL              false
#define DEF_NAMESERVER          "1.1.1.1,8.8.8.8,208.67.222.222"
#define DEF_CLUSTER_THRESHOLD   8
#define DEF_RECURSE_DEPTH       0


/* max/min num values for errors and warnings */
#define MAX_THRDS              256
#define MAX_DELAY              60
#define MAX_CONN_TIMEOUT       60
#define MAX_REQ_TIMEOUT        60
#define MIN_GLOB_TIMEOUT       600
#define MAX_CONN_CACHE         100
#define MIN_CLUSTER_THRESHOLD  2
#define MAX_CLUSTER_THRESHOLD  65535
#define MAX_RECURSE_DEPTH      10
#define MAX_EX_PATHS           64 + 1




/*******************************************************************************
 * VARS
 ******************************************************************************/


/* forward declaration - real def in attack.c since it's only used there */
struct hit_table;


/* contains every options (cmdline, default, etc.) */
typedef struct {
  const char *start_url;            /* target start url (-u) */
  url_T parsed_url;                 /* parsed start_url */
  char **attack_urls;               /* dyn. built attack urls */
  unsigned long num_attack_urls;    /* num attack urls */
  char *http_method;                /* http request method (-h) */
  long int *http_ex_codes;          /* exclude http status codes (-x) */
  size_t num_http_ex_codes;         /* num excluded http status codes */
  bool follow_redir;                /* follow redirect (-f) */
  long follow_redir_level;          /* max level to follow redirect (-i) */
  char *useragent;                  /* user-agent string (-U) */
  bool rand_ua;                     /* random user-agent (-G) */
  const char *http_header;          /* custom http header (-c) */
  const char *creds;                /* creds for http auth (-a) */
  bool autoref;                     /* auto update referrer (-r) */
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
  bool in_ssl;                      /* insecure ssl/tls mode (-i) */
  const char *cert_file;            /* client cert PEM (-E) for mTLS */
  const char *key_file;             /* client key PEM  (-y) for mTLS */
  const char *key_pass;             /* passphrase (-Y) for encrypted key */
  bool no_color;                    /* force colored output off (-N) */
  bool smart;                       /* anti-smart mode (-S) */
  unsigned short int cluster_threshold; /* smart cluster threshold (-K) */
  unsigned short int recurse_depth; /* max recursion depth (-d), 0 = off */
  char **exclude_paths;             /* dirs/paths to skip in recursion (-e) */
  size_t num_exclude_paths;         /* num exclude paths */
  const char *nameserver;           /* nameservers (-n) */
  const char *logfile;              /* logfile for found urls (-l) */
  const char *resume_file;          /* session file to resume from (-z) */
  unsigned long resume_word_offset; /* skip first N urls at level 0 on resume */
  char **resume_dirs;               /* dirs to seed into g_dirs on resume */
  size_t num_resume_dirs;
  /* ownership flags - tell free_lulzbuster() whether the named field is
   * heap-owned by us (set by load_session via xcalloc/split_csv) or
   * just a pointer into argv / a string literal */
  bool own_start_url;
  bool own_wordlist;
  bool own_extens;
  bool own_exclude_paths;
  long long min_resp_size;          /* min response body size (-m), 0 = off */
  long long max_resp_size;          /* max response body size (-M), 0 = off */
  /* response body regex filters. -b keeps only hits whose body matches,
   * -B drops hits whose body matches. compiled once in parse_opts and
   * regfree'd in free_lulzbuster. *_set is set when the user passed the
   * flag - matters because regex_t doesn't have a "compiled?" sentinel */
  const char *body_match;           /* raw -b pattern (argv ptr) */
  const char *body_exclude;         /* raw -B pattern (argv ptr) */
  regex_t body_match_re;            /* compiled -b pattern */
  regex_t body_exclude_re;          /* compiled -B pattern */
  bool body_match_set;
  bool body_exclude_set;
  unsigned char log_formats;        /* -O bitmask: LOG_FMT_BIT_*, 0 = none yet */
  /* one resolved path per format index (LOG_FMT_TEXT/CSV/JSONL).
   * NULL when that format isn't selected. own_log_paths[i]==1 means
   * heap-allocated by derive_logfile() and must be free()d on exit */
  char *log_paths[LOG_FMT_COUNT];
  bool own_log_paths[LOG_FMT_COUNT];
  /* session file path on graceful interrupt save. derived from
   * start_url like log_paths so multiple scans in the same cwd don't
   * clobber each other's session. heap-owned when set */
  char *session_path;
  wildcard_T wcard;                 /* wildcard table */
  struct hit_table *hits;           /* runtime cluster table (smart mode) */
  curl_T *curl;                     /* pointer to curl table */
} opts_T;
  /*} __attribute__((packed)) opts_T;*/


/*******************************************************************************
 * FUNCTION PROTOTYPES
 ******************************************************************************/


/* set static http (curl) options */
bool set_http_options(opts_T *);

/* dump the final-settings block to stderr right before the scan starts.
 * shows every relevant cmdline opt + derived state (resolved log paths,
 * smart-mode threshold, etc.). called from main once after parse_opts +
 * the logfile resolution dance */
void print_opts(const opts_T *);

/* set extensions and return num extensions */
void set_extensions(opts_T *);

/* set attack urls */
void set_attack_urls(opts_T *);

/* set default opts */
void set_default_opts(opts_T *);

/* parse cmdline opts */
void parse_opts(int, char **, opts_T *);


#endif

