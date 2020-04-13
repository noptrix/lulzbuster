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
* error.c                                                                      *
*                                                                              *
* AUTHOR                                                                       *
* noptrix@nullsecurity.net                                                     *
*                                                                              *
*******************************************************************************/


/* sys includes */


/* own includes */
#include "lulzbuster.h"
#include "error.h"


/* function prototypes */
static void _errorf(const char *);
static void _error(const char *);
static void _warn(const char *);
static void _sys_errorf(const char *);
static void _sys_warn(const char *);


/* error codes, messages and corresponding functions */
error_T error[] = {
  { W_SYS,              WARN_SYS,             _sys_warn },
  { E_SYS,              ERR_SYS,              _sys_errorf },
  { E_ARGC,             ERR_ARGC,             _errorf },
  { E_ARGS,             ERR_ARGS,             _errorf },
  { E_TARGET,           ERR_TARGET,           _errorf },
  { E_URL,              ERR_URL,              _errorf },
  { E_PORT,             ERR_PORT,             _errorf },
  { E_METH,             ERR_METH,             _errorf },
  { E_METH_LEN,         ERR_METH_LEN,         _errorf },
  { E_OLOG,             ERR_OLOG,             _errorf },
  { E_OFILE,            ERR_OFILE,            _errorf },
  { E_RFILE,            ERR_RFILE,            _errorf },
  { E_WFILE,            ERR_WFILE,            _errorf },
  { E_CFILE,            ERR_CFILE,            _errorf },
  { E_WLIST_CNT,        ERR_WLIST_CNT,        _errorf },
  { E_WLIST_RLN,        ERR_WLIST_RLN,        _errorf },
  { E_CREDS,            ERR_CREDS,            _errorf },
  { E_PCREDS,           ERR_PCREDS,           _errorf },
  { E_PROXY_ADDR,       ERR_PROXY_ADDR,       _errorf },
  { E_RDIR_NUM,         ERR_RDIR_NUM,         _errorf },
  { E_HTTP_VER,         ERR_HTTP_VER,         _errorf },
  { E_PTHR_MX_INIT,     ERR_PTHR_MX_INIT,     _error },
  { E_TCP_CONNECT,      ERR_TCP_CONNECT,      _error },
  { E_CURL_INIT,        ERR_CURL_INIT,        _error },
  { E_CURL_TCPFAST,     ERR_CURL_TCPFAST,     _error },
  { E_CURL_DNSCACHE,    ERR_CURL_DNSCACHE,    _error },
  { E_CURL_WF,          ERR_CURL_WF,          _error },
  { E_CURL_MAXCONNS,    ERR_CURL_MAXCONNS,    _error },
  { E_CURL_SSL_PEER,    ERR_CURL_SSL_PEER,    _error },
  { E_CURL_SSL_HOST,    ERR_CURL_SSL_HOST,    _error },
  { E_CURL_UAGENT,      ERR_CURL_UAGENT,      _error },
  { E_CURL_CREQUEST,    ERR_CURL_CREQUEST,    _error },
  { E_CURL_NOBODY,      ERR_CURL_NOBODY,      _error },
  { E_CURL_FOLLOW,      ERR_CURL_FOLLOW,      _error },
  { E_CURL_MAXRDIRS,    ERR_CURL_MAXRDIRS,    _error },
  { E_CURL_AREFER,      ERR_CURL_AREFER,      _error },
  { E_CURL_TIMEOUT,     ERR_CURL_TIMEOUT,     _error },
  { E_CURL_USERPWD,     ERR_CURL_USERPWD,     _error },
  { E_CURL_HTTPAUTH,    ERR_CURL_HTTPAUTH,    _error },
  { E_CURL_HTTPHDR,     ERR_CURL_HTTPHDR,     _error },
  { E_CURL_PROXY,       ERR_CURL_PROXY,       _error },
  { E_CURL_PAUTH,       ERR_CURL_PAUTH,       _error },
  { E_CURL_PCREDS,      ERR_CURL_PCREDS,      _error },
  { E_CURL_HTTPVER,     ERR_CURL_HTTPVER,     _error },
  { E_CURL_SLIST,       ERR_CURL_SLIST,       _error },
  { E_CURLSH_LDNS,      ERR_CURLSH_LDNS,      _error },
  { E_CURLSH_SSL,       ERR_CURLSH_SSL,       _error },
  { E_CURLSH_CONN,      ERR_CURLSH_CONN,      _error },
  { E_CURLSH_LF,        ERR_CURLSH_LF,        _error },
  { E_CURLSH_ULF,       ERR_CURLSH_ULF,       _error },
  { E_URL_PARSE,        ERR_URL_PARSE,        _errorf },
  { W_THRDS,            WARN_THRDS,           _warn },
  { W_DELAY,            WARN_DELAY,           _warn },
  { W_CONN_NUM,         WARN_CONN_NUM,        _warn },
  { W_READ_NUM,         WARN_READ_NUM,        _warn },
  { W_GLOB_NUM,         WARN_GLOB_NUM,        _warn },
  { W_UNLINK,           WARN_UNLINK,          _warn },
  { W_MAXCONN_CACHE,    WARN_MAXCONN_CACHE,   _warn },
  { W_PTHR_MX_DSTR,     WARN_PTHR_MX_DSTR,    _warn },
  { W_CLOG,             WARN_CLOG,            _warn },
  { W_CURL_CLNUP,       WARN_CURL_CLNUP,      _warn },
  { W_CURL_DNS,         WARN_CURL_DNS,        _warn },
};


/* generate (fatal) error message and exit prog */
static void _errorf(const char *msg)
{
  SLOG("%s", msg);
  __EXIT_FAILURE;

  return;
}


/* generate error message */
static void _error(const char *msg)
{
  SLOG("%s", msg);
}


/* generate warn messages */
static void _warn(const char *msg)
{
  SLOG("%s", msg);

  return;
}


/* generate (fatal) system error message and exit prog */
static void _sys_errorf(const char *msg)
{
  perror(msg);
  __EXIT_FAILURE;

  return;
}


/* generate system warn messages */
static void _sys_warn(const char *msg)
{
  perror(msg);

  return;
}


/* call one of our error functions above */
void err(const unsigned char ecode)
{
  __CALL_ERROR_FUNC(ecode);

  return;
}

