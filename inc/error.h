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


/* just shortenings */
#define RED   CRED PERR CRESET
#define YEL   CYELLOW PWARN CRESET


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
  W_CLOG, W_CURL_CLNUP, W_CURL_DNS,
};


/* error messages */
#define ERR_SYS             RED
#define ERR_ARGC            RED "use -H for help\n"
#define ERR_ARGS            RED "WTF? mount /dev/brain!\n"
#define ERR_TARGET          RED "yeah bitch, without target URL?!\n"
#define ERR_URL             RED "invalid target URL\n"
#define ERR_PORT            RED "invalid port number\n"
#define ERR_METH            RED "invalid HTTP request method\n"
#define ERR_METH_LEN        RED "wrong HTTP request method\n"
#define ERR_OLOG            RED "could not create/open logfile\n"
#define ERR_OFILE           RED "could not open wordlist\n"
#define ERR_RFILE           RED "could not read from wordlist\n"
#define ERR_WFILE           RED "could not create or open log file\n"
#define ERR_CFILE           RED "could not close file\n"
#define ERR_WLIST_CNT       RED "could not count lines from wordlist file\n"
#define ERR_WLIST_RLN       RED "could not readlines from wordlist file\n"
#define ERR_PROXY_ADDR      RED "invalid proxy addr\n"
#define ERR_CREDS           RED "invalid credentials for auth\n"
#define ERR_PCREDS          RED "invalid credentials for proxy auth\n"
#define ERR_RDIR_NUM        RED "max value for '-r' exceeded\n"
#define ERR_HTTP_VER        RED "invalid http version detected\n"
#define ERR_PTHR_MX_INIT    RED "could not init pthread mutex locks\n"
#define ERR_TCP_CONNECT     RED "could not connect to host:port on given URL\n"

/* curl error messages */
#define ERR_CURL_INIT       RED "could not init libcurl stuff\n"
#define ERR_CURL_TCPFAST    RED "could not set CURLOPT_TCP_FASTOPEN\n"
#define ERR_CURL_DNSCACHE   RED "could not set CURLOPT_DNS_CACHE_TIMEOUT\n"
#define ERR_CURL_WF         RED "could not set CURLOPT_WRITEFUNCTION\n"
#define ERR_CURL_MAXCONNS   RED "could not set CURLOPT_MAXCONNECTS\n"
#define ERR_CURL_SSL_PEER   RED "could not set CURLOPT_SSL_VERIFYPEER\n"
#define ERR_CURL_SSL_HOST   RED "could not set CURLOPT_SSL_VERIFYHOST\n"
#define ERR_CURL_UAGENT     RED "could not set CURLOPT_USERAGENT\n"
#define ERR_CURL_CREQUEST   RED "could not set CURLOPT_CUSTOMREQUEST\n"
#define ERR_CURL_NOBODY     RED "could not set CURLOPT_NOBODY\n"
#define ERR_CURL_FOLLOW     RED "could not set CURLOPT_FOLLOWLOCATION\n"
#define ERR_CURL_MAXRDIRS   RED "could not set CURLOPT_MAXREDIRS\n"
#define ERR_CURL_AREFER     RED "could not set CURLOPT_AUTOREFERER\n"
#define ERR_CURL_TIMEOUT    RED "could not set CURLOPT_TIMEOUT\n"
#define ERR_CURL_USERPWD    RED "could not set CURLOPT_USERPWD\n"
#define ERR_CURL_HTTPAUTH   RED "could not set CURLOPT_HTTPAUTH\n"
#define ERR_CURL_HTTPHDR    RED "could not set CURLOPT_HTTPHEADER\n"
#define ERR_CURL_PROXY      RED "could not set CURLOPT_PROXY\n"
#define ERR_CURL_PAUTH      RED "could not set CURLOPT_PROXYAUTH\n"
#define ERR_CURL_PCREDS     RED "could not set CURLOPT_PROXYUSERPWD\n"
#define ERR_CURL_HTTPVER    RED "could not set CURLOPT_HTTP_VERSION_*\n"
#define ERR_CURL_SLIST      RED "could not append custom header in curl\n"
#define ERR_CURLSH_LDNS     RED "could not set CURL_LOCK_DATA_DNS\n"
#define ERR_CURLSH_SSL      RED "could not set CURL_LOCK_DATA_SSL_SESSION\n"
#define ERR_CURLSH_CONN     RED "could not set CURL_LOCK_DATA_CONNECT\n"
#define ERR_CURLSH_LF       RED "could not set CURLSHOPT_LOCKFUNC\n"
#define ERR_CURLSH_ULF      RED "could not set CURLSHOPT_UNLOCKFUNC\n"
#define ERR_URL_PARSE       RED "could not parse start url\n"

/* warn messages */
#define WARN_SYS            YEL
#define WARN_THRDS          YEL "more than 256 threads? ...\n"
#define WARN_DELAY          YEL "more than 60s for delay? ...\n"
#define WARN_CONN_NUM       YEL "more than 60s for connection timeout? ...\n"
#define WARN_READ_NUM       YEL "more than 60s for read timeout? ...\n"
#define WARN_GLOB_NUM       YEL "less than 600s for global timeout? ...\n"
#define WARN_UNLINK         YEL "could not delete file\n"
#define WARN_MAXCONN_CACHE  YEL "more than 100 connection caches? ...\n"
#define WARN_PTHR_MX_DSTR   YEL "could not destroy pthread mutex locks\n"
#define WARN_CLOG           YEL "could not close logfile\n"

/* curl warn messages */
#define WARN_CURL_CLNUP     YEL "fuck ups with cleaning curl's shared object\n"
#define WARN_CURL_DNS       YEL \
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

