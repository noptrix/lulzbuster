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
* error.h                                                                      *
*                                                                              *
* AUTHOR                                                                       *
* noptrix@nullsecurity.net                                                     *
*                                                                              *
*******************************************************************************/


#ifndef ERROR_H
#define ERROR_H


/*******************************************************************************
 * INCLUDES
 ******************************************************************************/


/* sys includes */
#include <errno.h>


/* own includes */
#include "wrapper.h"
#include "log.h"


/*******************************************************************************
 * MACROS
 ******************************************************************************/


/* error codes */
enum {
  W_SYS, E_SYS, E_ARGC, E_ARGS, E_TARGET, E_URL, E_PORT, E_METH, E_METH_LEN,
  E_OLOG, E_OFILE, E_RFILE, E_WFILE, E_CFILE, E_WLIST_CNT, E_WLIST_RLN, E_CREDS,
  E_PCREDS, E_PROXY_ADDR, E_RDIR_NUM, E_HTTP_VER, E_PTHR_MX_INIT, E_TCP_CONNECT,
  E_CURL_INIT, E_CURL_TCPFAST, E_CURL_DNSCACHE, E_CURL_WF, E_CURL_MAXCONNS,
  E_CURL_SSL_PEER, E_CURL_SSL_HOST, E_CURL_UAGENT, E_CURL_CREQUEST,
  E_CURL_NOBODY, E_CURL_FOLLOW, E_CURL_MAXRDIRS, E_CURL_AREFER, E_CURL_TIMEOUT,
  E_CURL_USERPWD, E_CURL_HTTPAUTH, E_CURL_HTTPHDR, E_CURL_PROXY, E_CURL_PAUTH,
  E_CURL_PCREDS, E_CURL_HTTPVER, E_CURL_SLIST, E_CURLSH_LDNS, E_CURLSH_SSL,
  E_CURLSH_CONN, E_CURLSH_LF, E_CURLSH_ULF, E_URL_PARSE, W_THRDS, W_DELAY,
  W_CONN_NUM, W_READ_NUM, W_GLOB_NUM, W_UNLINK, W_MAXCONN_CACHE, W_PTHR_MX_DSTR,
  W_CLOG, W_CURL_CLNUP, W_CURL_DNS, E_SIZE, E_FMT,
  E_CURL_SSLCERT, E_CURL_SSLKEY, E_CURL_KEYPASS, E_RCERT, E_RKEY,
  E_REGEX,
};


/* error messages. colors + [-]/[!] prefix added at print time by the
 * functions in error.c so they pick up the runtime color ptrs */
#define ERR_SYS             ""
#define ERR_ARGC            "use -H for help\n"
#define ERR_ARGS            "WTF? mount /dev/brain!\n"
#define ERR_TARGET          "yeah bitch, without target URL?!\n"
#define ERR_URL             "invalid target URL\n"
#define ERR_PORT            "invalid port number\n"
#define ERR_METH            "invalid HTTP request method\n"
#define ERR_METH_LEN        "wrong HTTP request method\n"
#define ERR_OLOG            "could not create/open logfile\n"
#define ERR_OFILE           "could not open wordlist\n"
#define ERR_RFILE           "could not read from wordlist\n"
#define ERR_WFILE           "could not create or open log file\n"
#define ERR_CFILE           "could not close file\n"
#define ERR_WLIST_CNT       "could not count lines from wordlist file\n"
#define ERR_WLIST_RLN       "could not readlines from wordlist file\n"
#define ERR_PROXY_ADDR      "invalid proxy addr\n"
#define ERR_CREDS           "invalid credentials for auth\n"
#define ERR_PCREDS          "invalid credentials for proxy auth\n"
#define ERR_RDIR_NUM        "max value for '-r' exceeded\n"
#define ERR_HTTP_VER        "invalid http version detected\n"
#define ERR_PTHR_MX_INIT    "could not init pthread mutex locks\n"
#define ERR_TCP_CONNECT     "could not connect to host:port on given URL\n"

/* curl error messages */
#define ERR_CURL_INIT       "could not init libcurl stuff\n"
#define ERR_CURL_TCPFAST    "could not set CURLOPT_TCP_FASTOPEN\n"
#define ERR_CURL_DNSCACHE   "could not set CURLOPT_DNS_CACHE_TIMEOUT\n"
#define ERR_CURL_WF         "could not set CURLOPT_WRITEFUNCTION\n"
#define ERR_CURL_MAXCONNS   "could not set CURLOPT_MAXCONNECTS\n"
#define ERR_CURL_SSL_PEER   "could not set CURLOPT_SSL_VERIFYPEER\n"
#define ERR_CURL_SSL_HOST   "could not set CURLOPT_SSL_VERIFYHOST\n"
#define ERR_CURL_UAGENT     "could not set CURLOPT_USERAGENT\n"
#define ERR_CURL_CREQUEST   "could not set CURLOPT_CUSTOMREQUEST\n"
#define ERR_CURL_NOBODY     "could not set CURLOPT_NOBODY\n"
#define ERR_CURL_FOLLOW     "could not set CURLOPT_FOLLOWLOCATION\n"
#define ERR_CURL_MAXRDIRS   "could not set CURLOPT_MAXREDIRS\n"
#define ERR_CURL_AREFER     "could not set CURLOPT_AUTOREFERER\n"
#define ERR_CURL_TIMEOUT    "could not set CURLOPT_TIMEOUT\n"
#define ERR_CURL_USERPWD    "could not set CURLOPT_USERPWD\n"
#define ERR_CURL_HTTPAUTH   "could not set CURLOPT_HTTPAUTH\n"
#define ERR_CURL_HTTPHDR    "could not set CURLOPT_HTTPHEADER\n"
#define ERR_CURL_PROXY      "could not set CURLOPT_PROXY\n"
#define ERR_CURL_PAUTH      "could not set CURLOPT_PROXYAUTH\n"
#define ERR_CURL_PCREDS     "could not set CURLOPT_PROXYUSERPWD\n"
#define ERR_CURL_HTTPVER    "could not set CURLOPT_HTTP_VERSION_*\n"
#define ERR_CURL_SLIST      "could not append custom header in curl\n"
#define ERR_CURLSH_LDNS     "could not set CURL_LOCK_DATA_DNS\n"
#define ERR_CURLSH_SSL      "could not set CURL_LOCK_DATA_SSL_SESSION\n"
#define ERR_CURLSH_CONN     "could not set CURL_LOCK_DATA_CONNECT\n"
#define ERR_CURLSH_LF       "could not set CURLSHOPT_LOCKFUNC\n"
#define ERR_CURLSH_ULF      "could not set CURLSHOPT_UNLOCKFUNC\n"
#define ERR_URL_PARSE       "could not parse start url\n"
#define ERR_SIZE            "invalid size for -m/-M (use bytes or NK/NM/NG)\n"
#define ERR_FMT             "invalid -O format (use 'log','csv','jsonl','all' " \
                            "or comma list)\n"
#define ERR_CURL_SSLCERT    "could not set CURLOPT_SSLCERT\n"
#define ERR_CURL_SSLKEY     "could not set CURLOPT_SSLKEY\n"
#define ERR_CURL_KEYPASS    "could not set CURLOPT_KEYPASSWD\n"
#define ERR_RCERT           "could not read client cert file\n"
#define ERR_RKEY            "could not read client key file\n"
#define ERR_REGEX           "invalid regex for -b/-B\n"

/* warn messages */
#define WARN_SYS            ""
#define WARN_THRDS          "more than 256 threads? ...\n"
#define WARN_DELAY          "more than 60s for delay? ...\n"
#define WARN_CONN_NUM       "more than 60s for connection timeout? ...\n"
#define WARN_READ_NUM       "more than 60s for read timeout? ...\n"
#define WARN_GLOB_NUM       "less than 600s for global timeout? ...\n"
#define WARN_UNLINK         "could not delete file\n"
#define WARN_MAXCONN_CACHE  "more than 100 connection caches? ...\n"
#define WARN_PTHR_MX_DSTR   "could not destroy pthread mutex locks\n"
#define WARN_CLOG           "could not close logfile\n"

/* curl warn messages */
#define WARN_CURL_CLNUP     "fuck ups with cleaning curl's shared object\n"
#define WARN_CURL_DNS       \
  "could not set CURLOPT_DNS_SERVERS. using system's nameservers...\n"


/* call error function */
#define __CALL_ERROR_FUNC(code) error[code].fcall(error[code].msg);


/* debug foo */
#define TRACE \
  do { \
    fflush(NULL); \
    fprintf(stderr, "%s: %d: %s(): bitch! perror: ", __FILE__, __LINE__, \
            __func__); \
    perror(""); \
} while (0)


/* print opts_T opts */
#define DEBUG_INIT_OPTS \
  fprintf(stderr, "\n-- DEBUG --\n\n");\
  fprintf(stderr,\
         "start_url:            %s\n"\
         "attack_urls:          %s\n"\
         "http_method:          %s\n"\
         "follow_redir:         %u\n"\
         "follow_redir_level:   %ld\n"\
         "wordlist:             %s\n"\
         "extens:               %s\n"\
         "num_extens:           %lu\n"\
         "useragent:            %s\n"\
         "rand_ua               %d\n"\
         "http_header:          %s\n"\
         "creds:                %s\n"\
         "proxy:                %s\n"\
         "proxy_creds:          %s\n"\
         "http_version:         %s\n"\
         "threads:              %u\n"\
         "conn_cache:           %ld\n"\
         "delay:                %u\n"\
         "conn_timeout:         %ld\n"\
         "req_timeout:          %ld\n"\
         "glob_Timeout:         %u\n"\
         "logfile:              %s\n"\
         "nameserver:           %s\n", \
         opts->start_url, opts->attack_urls[0], opts->http_method, \
         opts->follow_redir, opts->follow_redir_level, opts->wordlist, \
         (opts->extens) ? opts->extens[0] : "unset", \
         opts->num_extens, opts->useragent, opts->rand_ua, opts->http_header,\
         opts->creds, opts->proxy, opts->proxy_creds, opts->http_version, \
         opts->threads, opts->conn_cache, opts->delay, opts->conn_timeout, \
         opts->req_timeout, opts->glob_timeout, \
         opts->logfile, opts->nameserver);\
  fprintf(stderr, "\n-- DEBUG --\n\n");


/*******************************************************************************
 * VARS
 ******************************************************************************/


/* error table */
typedef struct {
  const unsigned char code;       /* error code */
  const char *msg;                /* error message */
  void (*fcall)(const char *);    /* ptr to error-function */
} error_T;


/*******************************************************************************
 * FUNCTION PROTOTYPES
 ******************************************************************************/


/* user function for error reporting */
void err(const unsigned char);


#endif

