# Description

`lulzbuster` is a multithreaded, very fast and smart HTTP(S) directory and file
bruteforcer written in C on top of libcurl.

Given a target URL and a wordlist, it enumerates valid paths by firing
concurrent HTTP requests and reporting back the responses that look like real
hits (i.e. status codes the user did not exclude).

It is aimed at penetration testers, bug-bounty hunters and CTF players who want
a small, fast, scriptable tool that does one thing well.

The scan flow is:

- parse the wordlist and any user-supplied extensions (`-A`) into a flat list
  of attack URLs;
- fire a handful of probes against random URL shapes to detect a wildcard 200
  ("everything answers OK") and capture its (code, size) fingerprint;
- spin up *N* worker threads (`-t`) that share a libcurl share handle for DNS,
  SSL session and connection reuse;
- run each request, parse code/size/lines/words, and emit a row to stderr plus
  to any selected log files (`-O` / `-l`);
- optionally recurse into hits whose URL ends with `/` (`-d`);
- on Ctrl+C, SIGTERM, or a global timeout (`-T`) write a per-target session
  file so the scan can be resumed with `-z`.

Two modes of operation are worth calling out:

- **Default mode** — reports every response whose status code is not in the
  exclude list (`-x`). Fast, but noisy on sites that return 200 to everything.
- **Smart mode** (`-S`) — uses the wildcard fingerprint plus a
  (code, size_bucket) clustering table (`-K`) to suppress hits that look like
  wildcard noise. Slower because of the extra bookkeeping, but the output is
  far more actionable.

# Usage

```
$ lulzbuster -H
    __      __      __               __
   / /_  __/ /___  / /_  __  _______/ /____  _____
  / / / / / /_  / / __ \/ / / / ___/ __/ _ \/ ___/
 / / /_/ / / / /_/ /_/ / /_/ (__  ) /_/  __/ /
/_/\__,_/_/ /___/_.___/\__,_/____/\__/\___/_/

        --==[ by nullsecurity.net ] ==--

usage

  lulzbuster -s <arg> [opts] | <misc>

target options

  -s <url>       - start url to begin scan with

http options

  -h <type>      - http request type (default: GET) - ? to list types
  -x <code>      - exclude http status codes (default: 400,404,500,501,502,503
                   multi codes separated by ',')
  -f             - follow http redirects. hint: better try appending a '/'
                   with '-A' option first instead of using '-f'
  -F <num>       - num level to follow http redirects (default: 0)
  -u <str>       - user-agent string (default: built-in windows edge)
  -U             - use random built-in user-agents
  -c <str>       - pass custom header(s) (e.g. 'Cookie: foo=bar; lol=lulz')
  -a <creds>     - http auth credentials (format: <user>:<pass>)
  -r             - turn on auto update referrer
  -j <num>       - define http version (default: curl's default) - ? to list

tls options

  -i             - insecure mode (skips ssl/tls cert verification)
  -E <file>      - client cert file (PEM) for mTLS
  -y <file>      - client key file (PEM) for mTLS
  -Y <pass>      - passphrase for an encrypted client key

timeout options

  -D <num>       - num seconds for delay between requests (default: 0)
  -C <num>       - num seconds for connect timeout (default: 10)
  -R <num>       - num seconds for request timeout (default: 30)
  -T <num>       - num seconds to give up and exit lulzbuster completely
                   (default: none)

tuning options

  -t <num>       - num threads for concurrent scanning (default: 30)
  -g <num>       - num connection cache size for curl (default: 30)
                   note: this value should always equal to -t's value

wordlist options

  -w <file>      - wordlist file
                   (default: /usr/local/share/lulzbuster/lists/medium.txt)
  -A <str>       - append any words separated by comma (e.g. '/,.php,~bak)

proxy options

  -p <addr>      - proxy address (format: <scheme>://<host>:<port>) - ? to
                   list supported schemes
  -P <creds>     - proxy auth credentials (format: <user>:<pass>)

body filter options

  -m <size>      - skip hits with body smaller than <size> bytes.
                   suffix K/M/G accepted (e.g. 100, 10K, 5M)
  -M <size>      - skip hits with body bigger than <size> bytes.
                   suffix K/M/G accepted (e.g. 1M, 1G)
  -b <regex>     - keep only hits whose body matches the POSIX extended
                   regex (e.g. 'admin|login'). evaluated on first ~1MB
                   of body. complements -x (codes) and -m/-M (size)
  -B <regex>     - drop hits whose body matches the POSIX extended
                   regex (e.g. 'page not found'). useful against CMS
                   targets that return custom 200 'soft 404' pages

smart options

  -S             - smart mode aka: eliminate false-positives, show more
                   infos, etc. use this if speed is not your 1st priority!
  -K <num>       - smart mode cluster threshold (default: 8). after N
                   hits with same (code, size_bucket) further matches
                   are suppressed as wildcard noise

recursion options

  -d <num>       - max recursion depth (default: 0 = no recursion).
                   recurses into hits ending with '/' that returned
                   200/301/302/401/403
  -e <str>       - paths to exclude from recursion (substring match)
                   multi separated by ',' (e.g. '/admin/,logout')

output options

  -l <file>      - log hits to file. with single -O format the path
                   is used exact; with multiple formats the path is
                   a stem and '.<ext>' is appended per format. without
                   -O the format defaults to 'log' (text)
  -O <fmts>      - opt in to logging and pick format(s): 'log', 'csv',
                   'jsonl', 'all' or comma-list (e.g. 'log,jsonl').
                   without -l each format gets an auto-derived name
                   (e.g. https-www-nullsecurity-net_foo.<ext>)
  -N             - disable colored output (also auto-disabled when not
                   on a TTY or when NO_COLOR env var is set)

other options

  -n <str>       - nameservers (default: '1.1.1.1,8.8.8.8,208.67.222.222'
                   multi separated by ',')
  -z <file>      - resume from a session file written on prev ctrl+c
                   (only level 0 saves are supported)

misc

  -X             - print built-in user-agents
  -V             - print version of lulzbuster and exit
  -H             - print this help and exit
```

# Author

noptrix

# Notes

- clean code; real project
- lulzbuster is already packaged and available for [BlackArch
  Linux](https://www.blackarch.org/)
- My master-branches are always stable; dev-branches are created for current
  work.
- All of my public stuff you find are officially announced and published via
  [nullsecurity.net](https://www.nullsecurity.net/).

# License

Check docs/LICENSE.

# Disclaimer

We hereby emphasize, that the hacking related stuff found on
[nullsecurity.net](http://nullsecurity.net) are only for education purposes.
We are not responsible for any damages. You are responsible for your own
actions.
