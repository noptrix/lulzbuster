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
  CLOG(stderr, "%s%s%s%s\n", CBLUE, BANNER, CRESET, SUB_BANNER);

  return;
}


/* small helper so we don't repeat %s...%s for every section header */
#define HD(name)  "%s" name "%s\n\n"


/* print help and usage. headers go through CBOLD/CRESET runtime ptrs
 * so -N collapses them to no-color output cleanly */
void usage()
{
  CLOG(stderr,
  HD("usage")
  "  lulzbuster -s <arg> [opts] | <misc opts>\n\n"
  HD("target options")
  "  -s <url>       - start url to begin scan with\n\n"
  HD("http options")
  "  -h <type>      - http request type (default: GET) - ? to list types\n"
  "  -x <code>      - exclude http status codes (default: "DEF_HTTP_EX_CODES"\n"
  "                   multi codes separated by ',')\n"
  "  -f             - follow http redirects. hint: better try appending a '/'\n"
  "                   with '-A' option first instead of using '-f'\n"
  "  -F <num>       - num level to follow http redirects (default: 0)\n"
  "  -u <str>       - user-agent string (default: built-in windows edge)\n"
  "  -U             - use random built-in user-agents\n"
  "  -c <str>       - pass custom header(s) (e.g. 'Cookie: foo=bar; lol=lulz')\n"
  "  -a <creds>     - http auth credentials (format: <user>:<pass>)\n"
  "  -r             - turn on auto update referrer\n"
  "  -j <num>       - define http version (default: curl's default) - ? to list\n\n"
  HD("tls options")
  "  -i             - insecure mode (skips ssl/tls cert verification)\n"
  "  -E <file>      - client cert file (PEM) for mTLS\n"
  "  -y <file>      - client key file (PEM) for mTLS\n"
  "  -Y <pass>      - passphrase for an encrypted client key\n\n"
  HD("timeout options")
  "  -D <num>       - num seconds for delay between requests (default: 0)\n"
  "  -C <num>       - num seconds for connect timeout (default: 10)\n"
  "  -R <num>       - num seconds for request timeout (default: 30)\n"
  "  -T <num>       - num seconds to give up and exit lulzbuster completely\n"
  "                   (default: none)\n\n"
  HD("tuning options")
  "  -t <num>       - num threads for concurrent scanning (default: 35)\n"
  "  -g <num>       - num connection cache size for curl (default: 35)\n"
  "                   note: this value should always equal to -t's value\n\n"
  HD("wordlist options")
  "  -w <file>      - wordlist file\n"
  "                   (default: "DEF_WORDLIST")\n"
  "  -A <str>       - append any words separated by comma (e.g. '/,.php,~bak)\n\n"
  HD("proxy options")
  "  -p <addr>      - proxy address (format: <scheme>://<host>:<port>) - ? to\n"
  "                   list supported schemes\n"
  "  -P <creds>     - proxy auth credentials (format: <user>:<pass>)\n\n"
  HD("body filter options")
  "  -m <size>      - skip hits with body smaller than <size> bytes.\n"
  "                   suffix K/M/G accepted (e.g. 100, 10K, 5M)\n"
  "  -M <size>      - skip hits with body bigger than <size> bytes.\n"
  "                   suffix K/M/G accepted (e.g. 1M, 1G)\n"
  "  -b <regex>     - keep only hits whose body matches the POSIX extended\n"
  "                   regex (e.g. 'admin|login'). evaluated on first ~1MB\n"
  "                   of body. complements -x (codes) and -m/-M (size)\n"
  "  -B <regex>     - drop hits whose body matches the POSIX extended\n"
  "                   regex (e.g. 'page not found'). useful against CMS\n"
  "                   targets that return custom 200 'soft 404' pages\n\n"
  HD("smart options")
  "  -S             - smart mode aka: eliminate false-positives, show more\n"
  "                   infos, etc. use this if speed is not your 1st priority!\n"
  "  -K <num>       - smart mode cluster threshold (default: 8). after N\n"
  "                   hits with same (code, size_bucket) further matches\n"
  "                   are suppressed as wildcard noise\n\n"
  HD("recursion options")
  "  -d <num>       - max recursion depth (default: 0 = no recursion).\n"
  "                   recurses into hits ending with '/' that returned\n"
  "                   200/301/302/401/403\n"
  "  -e <str>       - paths to exclude from recursion (substring match)\n"
  "                   multi separated by ',' (e.g. '/admin/,logout')\n\n"
  HD("output options")
  "  -l <file>      - log hits to file. with single -O format the path\n"
  "                   is used exact; with multiple formats the path is\n"
  "                   a stem and '.<ext>' is appended per format. without\n"
  "                   -O the format defaults to 'log' (text)\n"
  "  -O <fmts>      - opt in to logging and pick format(s): 'log', 'csv',\n"
  "                   'jsonl', 'all' or comma-list (e.g. 'log,jsonl').\n"
  "                   without -l each format gets an auto-derived name\n"
  "                   (e.g. https-www-nullsecurity-net_foo.<ext>)\n"
  "  -N             - disable colored output (also auto-disabled when not\n"
  "                   on a TTY or when NO_COLOR env var is set)\n\n"
  HD("other options")
  "  -n <str>       - nameservers (default: '1.1.1.1,8.8.8.8,208.67.222.222'\n"
  "                   multi separated by ',')\n"
  "  -z <file>      - resume from a session file written on prev ctrl+c\n"
  "                   (only level 0 saves are supported)\n\n"
  HD("misc options")
  "  -X             - print built-in user-agents\n"
  "  -V             - print version of lulzbuster and exit\n"
  "  -H             - print this help and exit\n\n"
  HD("examples")
  "  # plain scan against a target with the default wordlist\n"
  "  $ lulzbuster -s https://example.com/\n\n"
  "  # smart-mode scan with extensions, recursion and multi-format logging\n"
  "  $ lulzbuster -s https://target/ -w lists/big.txt -A '.php,.html,/' \\\n"
  "               -S -d 2 -O all\n\n"
  "  # body regex filter to drop CMS soft-404s\n"
  "  $ lulzbuster -s https://target/ -B 'page not found|does not exist'\n\n"
  "  # polite scan via socks5 proxy with a delay between requests\n"
  "  $ lulzbuster -s http://intranet.local/ -t 5 -D 1 \\\n"
  "               -p socks5h://127.0.0.1:9050\n\n"
  "  # resume an interrupted scan\n"
  "  $ lulzbuster -z https-target-com.session\n\n"
  ,
  CBOLD, CRESET,    /* usage */
  CBOLD, CRESET,    /* target */
  CBOLD, CRESET,    /* http */
  CBOLD, CRESET,    /* tls */
  CBOLD, CRESET,    /* timeout */
  CBOLD, CRESET,    /* tuning */
  CBOLD, CRESET,    /* wordlist */
  CBOLD, CRESET,    /* proxy */
  CBOLD, CRESET,    /* body filter */
  CBOLD, CRESET,    /* smart */
  CBOLD, CRESET,    /* recursion */
  CBOLD, CRESET,    /* output */
  CBOLD, CRESET,    /* other */
  CBOLD, CRESET,    /* misc */
  CBOLD, CRESET     /* examples */
  );

  return;
}

