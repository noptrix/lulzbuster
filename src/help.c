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
* help.h                                                                       *
*                                                                              *
* AUTHOR                                                                       *
* noptrix@nullsecurity.net                                                     *
*                                                                              *
*******************************************************************************/


/* sys includes */

/* own includes */
#include "help.h"
#include "lulzbuster.h"
#include "log.h"


/* leet banner, very important */
void banner()
{
  CLOG(stderr, "%s\n", CBLUE BANNER CRESET SUB_BANNER);

  return;
}


/* print help and usage */
void usage()
{
  CLOG(stderr, "%s",
  CBOLD"usage"CRESET"\n\n"
  "  lulzbuster -s <arg> [opts] | <misc>\n\n"
  CBOLD"target options"CRESET"\n\n"
  "  -s <url>       - start url to begin scan with\n\n"
  CBOLD"http options"CRESET"\n\n"
  "  -h <type>      - http request type (default: GET) - ? to list types\n"
  "  -x <code>      - exclude http status codes (default: "DEF_HTTP_EX_CODES"\n"
  "                   multi codes separated by ',')\n"
  "  -f             - follow http redirects. hint: better try appending a '/'\n"
  "                   with '-A' option first instead of using '-f'\n"
  "  -F <num>       - num level to follow http redirects (default: 0)\n"
  "  -u <str>       - user-agent string (default: built-in windows firefox)\n"
  "  -U             - use random built-in user-agents\n"
  "  -c <str>       - pass custom header(s) (e.g. 'Cookie: foo=bar; lol=lulz')\n"
  "  -a <creds>     - http auth credentials (format: <user>:<pass>)\n"
  "  -r             - turn on auto update referrer\n"
  "  -j <num>       - define http version (default: curl's default) - ? to list"
  CBOLD"\n\ntimeout options"CRESET"\n\n"
  "  -D <num>       - num seconds for delay between requests (default: 0)\n"
  "  -C <num>       - num seconds for connect timeout (default: 10)\n"
  "  -R <num>       - num seconds for request timeout (default: 30)\n"
  "  -T <num>       - num seconds to give up and exit lulzbuster completely\n"
  "                   (default: none)\n\n"
  CBOLD"tuning options"CRESET"\n\n"
  "  -t <num>       - num threads for concurrent scanning (default: 30)\n"
  "  -g <num>       - num connection cache size for curl (default: 30)\n"
  "                   note: this value should always equal to -t's value\n\n"
  CBOLD"other options"CRESET"\n\n"
  "  -w <file>      - wordlist file\n"
  "                   (default: "DEF_WORDLIST")\n"
  "  -A <str>       - append any words separated by comma (e.g. '/,.php,~bak)\n"
  "  -p <addr>      - proxy address (format: <scheme>://<host>:<port>) - ? to\n"
  "                   list supported schemes\n"
  "  -P <creds>     - proxy auth credentials (format: <user>:<pass>)\n"
  "  -i             - insecure mode (skips ssl/tls cert verification)\n"
  "  -S             - smart mode aka eliminate false-positives, more infos,\n"
  "                   etc. (use this if speed is not your 1st priority!)\n"
  "  -n <str>       - nameservers (default: '1.1.1.1,8.8.8.8,208.67.222.222'\n"
  "                   multi separated by '.')\n"
  "  -l <file>      - log found paths and valid urls to file\n\n"
  CBOLD"misc"CRESET"\n\n"
  "  -X             - print built-in user-agents\n"
  "  -V             - print version of lulzbuster and exit\n"
  "  -H             - print this help and exit\n\n"
  );

  return;
}

