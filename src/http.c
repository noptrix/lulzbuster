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
* http.c                                                                       *
*                                                                              *
* AUTHOR                                                                       *
* noptrix@nullsecurity.net                                                     *
*                                                                              *
*******************************************************************************/


/* sys includes */
#include <string.h>
#include <time.h>
#include <stdint.h>


/* own includes */
#include "http.h"
#include "wrapper.h"
#include "log.h"
#include "error.h"
#include "lulzbuster.h"


/* built-in user-agents list - mix of legacy + modern (2024-2026) UAs
 * across desktop / mobile / bot. order doesn't matter, get_rand_useragent
 * picks uniformly at random */
static useragents_T useragents[] = {
  /* === windows desktop === */
  {"windows", "chrome", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"},
  {"windows", "chrome", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"},
  {"windows", "chrome", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"},
  {"windows", "chrome", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"},
  {"windows", "chrome", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36"},
  {"windows", "chrome", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"},
  {"windows", "chrome", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"},
  {"windows", "chrome", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"},
  {"windows", "chrome", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"},
  {"windows", "chrome", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4034.0 Safari/537.36"},
  {"windows", "chrome", "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.130 Safari/537.36"},
  {"windows", "edge", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0"},
  {"windows", "edge", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0"},
  {"windows", "edge", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0"},
  {"windows", "edge", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0"},
  {"windows", "edge", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"},
  {"windows", "edge", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.18363"},
  {"windows", "firefox", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:141.0) Gecko/20100101 Firefox/141.0"},
  {"windows", "firefox", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0"},
  {"windows", "firefox", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0"},
  {"windows", "firefox", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0"},
  {"windows", "firefox", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0"},
  {"windows", "firefox", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0"},
  {"windows", "firefox", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:72.0) Gecko/20100101 Firefox/72.0"},
  {"windows", "opera", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 OPR/124.0.0.0"},
  {"windows", "opera", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 OPR/115.0.0.0"},
  {"windows", "opera", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0"},
  {"windows", "vivaldi", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Vivaldi/7.0.3495.27"},
  {"windows", "vivaldi", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Vivaldi/6.9.3447.54"},
  {"windows", "brave", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Brave/138"},
  {"windows", "brave", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"},

  /* === macos desktop === */
  {"macos", "safari", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Safari/605.1.15"},
  {"macos", "safari", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15"},
  {"macos", "safari", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15"},
  {"macos", "safari", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15"},
  {"macos", "safari", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"},
  {"macos", "safari", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.4 Safari/605.1.15"},
  {"macos", "chrome", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"},
  {"macos", "chrome", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"},
  {"macos", "chrome", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"},
  {"macos", "chrome", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"},
  {"macos", "chrome", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.130 Safari/537.36"},
  {"macos", "firefox", "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:141.0) Gecko/20100101 Firefox/141.0"},
  {"macos", "firefox", "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.0; rv:135.0) Gecko/20100101 Firefox/135.0"},
  {"macos", "firefox", "Mozilla/5.0 (Macintosh; Intel Mac OS X 13.6; rv:128.0) Gecko/20100101 Firefox/128.0"},
  {"macos", "firefox", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0"},
  {"macos", "firefox", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:72.0) Gecko/20100101 Firefox/72.0"},
  {"macos", "edge", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0"},
  {"macos", "edge", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0"},
  {"macos", "opera", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 OPR/124.0.0.0"},
  {"macos", "arc", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"},
  {"macos", "brave", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"},

  /* === linux desktop === */
  {"linux", "chrome", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"},
  {"linux", "chrome", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"},
  {"linux", "chrome", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"},
  {"linux", "chrome", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"},
  {"linux", "chrome", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"},
  {"linux", "chrome", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.130 Safari/537.36"},
  {"linux", "firefox", "Mozilla/5.0 (X11; Linux x86_64; rv:141.0) Gecko/20100101 Firefox/141.0"},
  {"linux", "firefox", "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"},
  {"linux", "firefox", "Mozilla/5.0 (X11; Linux x86_64; rv:135.0) Gecko/20100101 Firefox/135.0"},
  {"linux", "firefox", "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"},
  {"linux", "firefox", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:141.0) Gecko/20100101 Firefox/141.0"},
  {"linux", "firefox", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:135.0) Gecko/20100101 Firefox/135.0"},
  {"linux", "firefox", "Mozilla/5.0 (X11; Linux i686; rv:128.0) Gecko/20100101 Firefox/128.0"},
  {"linux", "firefox", "Mozilla/5.0 (X11; Linux x86_64; rv:72.0) Gecko/20100101 Firefox/72.0"},
  {"linux", "firefox", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:72.0) Gecko/20100101 Firefox/72.0"},
  {"linux", "edge", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0"},
  {"linux", "edge", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0"},
  {"linux", "opera", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 OPR/124.0.0.0"},
  {"linux", "vivaldi", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Vivaldi/7.0.3495.27"},
  {"linux", "brave", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"},
  {"linux", "links", "Links (2.30; Linux 6.8.0-generic x86_64; GNU C 13.2; text)"},
  {"linux", "lynx", "Lynx/2.9.2 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/3.8"},
  {"linux", "midori", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0 Safari/605.1.15 Midori/9"},
  {"linux", "thunderbird", "Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Thunderbird/115.0"},
  {"linux", "thunderbird", "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Thunderbird/128.0"},

  /* === android mobile === */
  {"android", "chrome", "Mozilla/5.0 (Linux; Android 15; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36"},
  {"android", "chrome", "Mozilla/5.0 (Linux; Android 15; Pixel 9 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36"},
  {"android", "chrome", "Mozilla/5.0 (Linux; Android 15; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Mobile Safari/537.36"},
  {"android", "chrome", "Mozilla/5.0 (Linux; Android 14; SM-S921B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36"},
  {"android", "chrome", "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36"},
  {"android", "chrome", "Mozilla/5.0 (Linux; Android 13; SM-A536B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"},
  {"android", "chrome", "Mozilla/5.0 (Linux; Android 12; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Mobile Safari/537.36"},
  {"android", "chrome", "Mozilla/5.0 (Linux; Android 10; ONEPLUS A6013) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.116 Mobile Safari/537.36"},
  {"android", "firefox", "Mozilla/5.0 (Android 15; Mobile; rv:141.0) Gecko/141.0 Firefox/141.0"},
  {"android", "firefox", "Mozilla/5.0 (Android 14; Mobile; rv:135.0) Gecko/135.0 Firefox/135.0"},
  {"android", "firefox", "Mozilla/5.0 (Android 13; Mobile; rv:128.0) Gecko/128.0 Firefox/128.0"},
  {"android", "firefox", "Mozilla/5.0 (Android 12; Mobile; rv:120.0) Gecko/120.0 Firefox/120.0"},
  {"android", "samsung", "Mozilla/5.0 (Linux; Android 15; SAMSUNG SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/27.0 Chrome/138.0.0.0 Mobile Safari/537.36"},
  {"android", "samsung", "Mozilla/5.0 (Linux; Android 14; SAMSUNG SM-S921B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/25.0 Chrome/130.0.0.0 Mobile Safari/537.36"},
  {"android", "samsung", "Mozilla/5.0 (Linux; Android 13; SAMSUNG SM-A536B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/22.0 Chrome/120.0.0.0 Mobile Safari/537.36"},
  {"android", "edge", "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Mobile Safari/537.36 EdgA/138.0.0.0"},
  {"android", "opera", "Mozilla/5.0 (Linux; Android 14; SM-S921B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36 OPR/85.0.0.0"},
  {"android", "brave", "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Mobile Safari/537.36"},
  {"android", "duckduckgo", "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/130.0.0.0 Mobile DuckDuckGo/5 Safari/537.36"},

  /* === ios mobile === */
  {"ios", "safari", "Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Mobile/22F76 Safari/604.1"},
  {"ios", "safari", "Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Mobile/22C152 Safari/604.1"},
  {"ios", "safari", "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/22A348 Safari/604.1"},
  {"ios", "safari", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/21F90 Safari/604.1"},
  {"ios", "safari", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/21A329 Safari/604.1"},
  {"ios", "safari", "Mozilla/5.0 (iPad; CPU OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Mobile/22F76 Safari/604.1"},
  {"ios", "safari", "Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/21F90 Safari/604.1"},
  {"ios", "chrome", "Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/142.0.0.0 Mobile/22F76 Safari/604.1"},
  {"ios", "chrome", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/130.0.0.0 Mobile/21F90 Safari/604.1"},
  {"ios", "firefox", "Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/141.0 Mobile/22F76 Safari/605.1.15"},
  {"ios", "firefox", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/125.0 Mobile/21A329 Safari/605.1.15"},
  {"ios", "edge", "Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 EdgiOS/138.0.0.0 Mobile/22C152 Safari/605.1.15"},
  {"ios", "duckduckgo", "Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) DuckDuckGo/8 Mobile/22F76 Safari/605.1.15"},

  /* === chromiumos === */
  {"chromiumos", "chrome", "Mozilla/5.0 (X11; CrOS x86_64 15748.81.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"},
  {"chromiumos", "chrome", "Mozilla/5.0 (X11; CrOS aarch64 15633.69.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"},
  {"chromiumos", "chrome", "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"},

  /* === bsd-flavored === */
  {"freebsd", "firefox", "Mozilla/5.0 (X11; FreeBSD amd64; rv:135.0) Gecko/20100101 Firefox/135.0"},
  {"freebsd", "firefox", "Mozilla/5.0 (X11; FreeBSD amd64; rv:128.0) Gecko/20100101 Firefox/128.0"},
  {"freebsd", "chrome", "Mozilla/5.0 (X11; FreeBSD amd64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"},
  {"openbsd", "firefox", "Mozilla/5.0 (X11; OpenBSD amd64; rv:128.0) Gecko/20100101 Firefox/128.0"},
  {"openbsd", "firefox", "Mozilla/5.0 (X11; OpenBSD amd64; rv:115.0) Gecko/20100101 Firefox/115.0"},
  {"openbsd", "chrome", "Mozilla/5.0 (X11; OpenBSD amd64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"},
  {"netbsd", "firefox", "Mozilla/5.0 (X11; NetBSD amd64; rv:128.0) Gecko/20100101 Firefox/128.0"},

  /* === bots / crawlers === */
  {"bot", "googlebot", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"},
  {"bot", "googlebot-mobile", "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"},
  {"bot", "googlebot-image", "Googlebot-Image/1.0"},
  {"bot", "bingbot", "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"},
  {"bot", "duckduckbot", "Mozilla/5.0 (compatible; DuckDuckBot-Https/1.1; https://duckduckgo.com/duckduckbot)"},
  {"bot", "yandexbot", "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)"},
  {"bot", "baiduspider", "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)"},
  {"bot", "ahrefsbot", "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)"},
  {"bot", "semrushbot", "Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)"},
  {"bot", "mj12bot", "Mozilla/5.0 (compatible; MJ12bot/v1.4.8; http://mj12bot.com/)"},
  {"bot", "facebookbot", "Mozilla/5.0 (compatible; facebookexternalhit/1.1; +http://www.facebook.com/externalhit_uatext.php)"},
  {"bot", "twitterbot", "Twitterbot/1.0"},
  {"bot", "linkedinbot", "LinkedInBot/1.0 (compatible; Mozilla/5.0; Apache-HttpClient +http://www.linkedin.com)"},
  {"bot", "telegrambot", "TelegramBot (like TwitterBot)"},
  {"bot", "discordbot", "Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)"},
  {"bot", "slackbot", "Slackbot 1.0 (+https://api.slack.com/robots)"},
  {"bot", "applebot", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15 (Applebot/0.1; +http://www.apple.com/go/applebot)"},
  {"bot", "petalbot", "Mozilla/5.0 (compatible; PetalBot; +https://webmaster.petalsearch.com/site/petalbot)"},
  {"bot", "msie", "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)"},

  /* === ai/llm crawlers (newer kids on the block) === */
  {"bot", "gptbot", "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.2; +https://openai.com/gptbot"},
  {"bot", "chatgpt-user", "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot"},
  {"bot", "claudebot", "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ClaudeBot/1.0; +claudebot@anthropic.com"},
  {"bot", "perplexitybot", "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot"},
  {"bot", "ccbot", "Mozilla/5.0 (compatible; CCBot/2.0; +https://commoncrawl.org/faq/)"},
  {"bot", "google-extended", "Mozilla/5.0 (compatible; Google-Extended/1.0; +https://developers.google.com/search/docs/crawling-indexing/overview-google-crawlers)"},
  {"bot", "bytespider", "Mozilla/5.0 (Linux; U; Android 5.0; en-US; MZ-M3 Note Build/LRX21V) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 UCBrowser/11.0.5.850 U3/0.8.0 Mobile Safari/534.30; Bytespider; spider-feedback@bytedance.com"},

  /* === legacy entries kept for variety === */
  {"chromiumos", "chrome", "Mozilla/5.0 (X11; CrOS aarch64 12607.58.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.86 Safari/537.36"},
  {"linux", "opera", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.80 Safari/537.36 OPR/62.0.3331.14"},
  {"linux", "vivaldi", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.134 Safari/537.36 Vivaldi/2.5.1525.40"},
  {"freebsd", "chrome", "Mozilla/5.0 (X11; FreeBSD amd64; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Iridium/2019.04 Safari/537.36 Chrome/73.0.0.0"},
};


/* pthread mutex locks */
static pthread_mutex_t locks[NUM_LOCKS];


/* generate a random url for the given pattern index. each pattern
 * resembles a different URL "shape" the user might scan, so we can
 * catch sites that respond differently per pattern. picks the right
 * format string based on whether `url` already has a trailing slash,
 * so recursion targets like ".../admin/" don't end up with "//" */
static char *rand_url(const char *url, size_t pattern_idx)
{
  char *randurl = NULL;
  const char *fmt = NULL;
  int r1 = rand();
  int r2 = rand();
  size_t ulen = strlen(url);
  bool ts = (ulen > 0 && url[ulen - 1] == '/');
  size_t need = 0;

  switch (pattern_idx) {
    case 0: /* random file with extension */
      fmt = ts ? "%s%d.txt" : "%s/%d.txt";
      need = snprintf(NULL, 0, fmt, url, r1) + 1;
      randurl = xcalloc(1, need);
      snprintf(randurl, need, fmt, url, r1);
      break;
    case 1: /* random "directory" */
      fmt = ts ? "%s%d/" : "%s/%d/";
      need = snprintf(NULL, 0, fmt, url, r1) + 1;
      randurl = xcalloc(1, need);
      snprintf(randurl, need, fmt, url, r1);
      break;
    case 2: /* random no extension */
      fmt = ts ? "%s%d" : "%s/%d";
      need = snprintf(NULL, 0, fmt, url, r1) + 1;
      randurl = xcalloc(1, need);
      snprintf(randurl, need, fmt, url, r1);
      break;
    case 3: /* deeper random path */
      fmt = ts ? "%s%d/%d/" : "%s/%d/%d/";
      need = snprintf(NULL, 0, fmt, url, r1, r2) + 1;
      randurl = xcalloc(1, need);
      snprintf(randurl, need, fmt, url, r1, r2);
      break;
    case 4: /* random extension */
    default:
      fmt = ts ? "%s%d.%d" : "%s/%d.%d";
      need = snprintf(NULL, 0, fmt, url, r1, r2) + 1;
      randurl = xcalloc(1, need);
      snprintf(randurl, need, fmt, url, r1, r2);
      break;
  }

  return randurl;
}


/* connection check and wildcard detection. fires MAX_WCARD_PROBES probes
 * at different URL shapes and records the unique (code, size) tuples so
 * attack() can suppress hits matching any of them in smart mode. honors
 * proxy + proxy_creds so we don't bypass the user's proxy on networks
 * where direct egress is blocked */
wildcard_T check_conn_wildcard(const char *url, const char *proxy,
                               const char *proxy_creds, bool in_ssl,
                               const char *cert, const char *key,
                               const char *key_pass, long conn_timeout)
{
  wildcard_T wcard = {0};
  size_t i = 0, j = 0;
  bool already = false;
  /* mirror set_http_options(): default verifies, -i flips both off */
  long verify_peer = in_ssl ? 0L : 1L;
  long verify_host = in_ssl ? 0L : 2L;

  for (i = 0; i < MAX_WCARD_PROBES; ++i) {
    char *randurl = rand_url(url, i);
    CURL *curl = curl_easy_init();
    CURLcode res = 0;
    long code = 0;
    curl_off_t size = 0;

    if (curl == NULL) {
      free(randurl);
      continue;
    }

    curl_easy_setopt(curl, CURLOPT_URL, randurl);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, conn_timeout);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &write_cb);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, verify_peer);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, verify_host);
    if (cert)     curl_easy_setopt(curl, CURLOPT_SSLCERT, cert);
    if (key)      curl_easy_setopt(curl, CURLOPT_SSLKEY, key);
    if (key_pass) curl_easy_setopt(curl, CURLOPT_KEYPASSWD, key_pass);
    if (proxy != NULL) {
      curl_easy_setopt(curl, CURLOPT_PROXY, proxy);
      if (proxy_creds != NULL) {
        curl_easy_setopt(curl, CURLOPT_PROXYAUTH, CURLAUTH_ANY);
        curl_easy_setopt(curl, CURLOPT_PROXYUSERPWD, proxy_creds);
      }
    }
    res = curl_easy_perform(curl);

    if (res == CURLE_OK) {
      curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
      curl_easy_getinfo(curl, CURLINFO_SIZE_DOWNLOAD_T, &size);

      wcard.conn_ok = true;
      if (code == HTTP_OK) {
        wcard.any_http_ok = true;
      }

      /* dedup: only store unique (code, size) tuples */
      already = false;
      for (j = 0; j < wcard.num_fps; ++j) {
        if (wcard.fps[j].resp_code == code &&
            wcard.fps[j].resp_size == size) {
          already = true;
          break;
        }
      }
      if (!already && wcard.num_fps < MAX_WCARD_PROBES) {
        wcard.fps[wcard.num_fps].resp_code = code;
        wcard.fps[wcard.num_fps].resp_size = size;
        wcard.num_fps++;
      }
    }

    free(randurl);
    curl_easy_cleanup(curl);
  }

  return wcard;
}


/* parse a given url */
url_T parse_url(const char *url)
{
  static url_T parsed_url;
  CURLUcode rc = 0;
  CURLU *purl = curl_url();

  /* i know this is weird but for now it's enough if either of one fails to
   * thell then: ERR_URL_PARSE. just to save code lines :) if needed i can
   * change later for individual error handling. also, this would rarely happen
   * since we check for valid url before */
  rc = curl_url_set(purl, CURLUPART_URL, url, 0);
  rc = curl_url_get(purl, CURLUPART_SCHEME, &parsed_url.scheme, 0);
  rc = curl_url_get(purl, CURLUPART_HOST, &parsed_url.host, 0);
  rc = curl_url_get(purl, CURLUPART_PORT, &parsed_url.port, CURLU_DEFAULT_PORT);
  rc = curl_url_get(purl, CURLUPART_PATH, &parsed_url.path, 0);

  if (rc != CURLUE_OK) {
    free_parsed_url(parsed_url);
    err(E_URL_PARSE);
  }

  curl_url_cleanup(purl);

  return parsed_url;
}


/* randomly fetch an useragent from useragents tables. workers call
 * this concurrently so we can't use plain rand() (shares global state,
 * not thread-safe per POSIX). thread-local seed + rand_r() instead.
 * seed is lazy-init'd on first call per thread from time + a tid hash */
const char *get_rand_useragent()
{
  static __thread unsigned int seed = 0;
  register size_t size = ARRAY_SIZE(useragents);

  if (seed == 0) {
    seed = (unsigned int) time(NULL) ^
           (unsigned int)(uintptr_t) pthread_self();
    if (seed == 0) seed = 1;  /* rand_r dislikes 0 in some impls */
  }
  return useragents[rand_r(&seed) % size].ua;
}


/* simply print built-in user-agent list (-A) */
void print_useragents()
{
  char *buff = NULL, *fmtstr = "%-10s | %-11s | %s\n";
  register size_t i = 0, len = 0, num_items = 0;

  num_items = ARRAY_SIZE(useragents);

  JSLOG("found %lu user-agents\n\n", num_items);
  SLOG("      %-12s %-13s %s\n\n", "OS", "Browser", "User-Agent");
  for (i = 0; i < num_items; ++i) {
    len = (strlen(useragents[i].os) + 1 + strlen(useragents[i].browser) + 1 + \
           strlen(useragents[i].ua) + 1) * sizeof(char *);
    len += snprintf(NULL, 0, fmtstr, useragents[i].os, useragents[i].browser,
                    useragents[i].ua) + 1;
    buff = xcalloc(1, len);
    snprintf(buff, len, fmtstr, useragents[i].os, useragents[i].browser,
             useragents[i].ua);
    VSLOG(buff);
    free(buff);
  }
  SLOG("\n");

  return;
}


/* do some necessary curl related cleanups */
bool cleanup_http(curl_T *curl)
{
  curl_slist_free_all(curl->list);
  curl_share_cleanup(curl->sh);
  curl_easy_cleanup(curl->eh);
  curl_global_cleanup();

  return true;
}


/* do some necessary curl related inits */
bool init_http(curl_T *curl)
{
  register bool check_ok = true;

  /* seed the PRNG once - used by rand_url() and get_rand_useragent() */
  srand((unsigned int) time(NULL));

  /* curl global init */
  if (curl_global_init(CURL_GLOBAL_ALL) != 0) {
    check_ok = false;
  }

  /* initial handler init. will be duplicated for worker threads! */
  curl->eh = curl_easy_init();
  if (curl->eh == NULL) {
    check_ok = false;
  }

  /* init shared object for easy handler */
  curl->sh = curl_share_init();
  if (curl->sh == NULL) {
    check_ok = false;
  }

  if (!check_ok) {
    err(E_CURL_INIT);
    return check_ok;
  }

  /* init curl's linked list for our headers and other options we dyn. set. */
  curl->list = NULL;

  return check_ok;
}


/* unlock callback func for curl */
void unlock_cb(CURL *handle, curl_lock_data data, void *userptr)
{
  (void) handle;
  (void) userptr;

  pthread_mutex_unlock(&locks[data]);

  return;
}


/* lock callback func for curl */
void lock_cb(CURL *handle, curl_lock_data data, curl_lock_access access,
             void *userptr)
{
  (void) handle;
  (void) access;
  (void) userptr;

  pthread_mutex_lock(&locks[data]);

  return;
}


/* destroy initiated locks */
bool kill_locks(void)
{
  register size_t i = 0;

  for (i = 0; i < NUM_LOCKS; ++i) {
    if (pthread_mutex_destroy(&locks[i]) != 0) {
      err(W_PTHR_MX_DSTR);
      return false;
    }
  }

  return true;
}


/* init pthread mutex locks */
bool init_locks(void)
{
  register size_t i = 0;

  for (i = 0; i < NUM_LOCKS; ++i) {
    if (pthread_mutex_init(&locks[i], NULL) != 0) {
      err(E_PTHR_MX_INIT);
      return false;
    }
  }

  return true;
}


/* write callback func for curl. if userptr points to a body_stats_T we
 * count bytes/newlines/words on the fly. word counting tracks
 * in_word state across chunks so we don't double-count */
size_t write_cb(void *buff, register size_t size, register size_t nmemb,
                void *userptr)
{
  register size_t total = size * nmemb;
  body_stats_T *st = (body_stats_T *) userptr;

  if (st) {
    register const unsigned char *b = (const unsigned char *) buff;
    register size_t i = 0;
    register bool in_word = st->in_word;
    register unsigned char c = 0;
    register bool is_ws = false;

    for (i = 0; i < total; ++i) {
      c = b[i];
      is_ws = (c == ' ' || c == '\t' || c == '\n' || c == '\r');
      if (c == '\n') {
        st->lines++;
      }
      if (!is_ws && !in_word) {
        st->words++;
        in_word = true;
      } else if (is_ws && in_word) {
        in_word = false;
      }
    }

    st->bytes += total;
    st->in_word = in_word;

    /* opt-in body capture for -b/-B regex matching. only active when
     * the worker pre-allocated st->buf, otherwise we skip the memcpy
     * entirely. truncate at buf_cap since regex matching the head of
     * the body catches the signal we care about (titles, error text,
     * auth markers) and keeps memory bounded */
    if (st->buf != NULL && st->buf_len < st->buf_cap) {
      size_t room = st->buf_cap - st->buf_len;
      size_t take = total < room ? total : room;
      memcpy(st->buf + st->buf_len, buff, take);
      st->buf_len += take;
    }
  }

  return total; /* curl wants this otherwise we get '23' error code */
}


/* do http request for our attack worker thread */
bool do_req(const char *url, CURL *handler, CURLSH *share)
{
  register bool check_ok = true;
  /*static unsigned char num_err = 0;
  CURLcode res = 0;*/

  /* set url and use shared object for our easy handlers */
  curl_easy_setopt(handler, CURLOPT_URL, url);
  curl_easy_setopt(handler, CURLOPT_SHARE, share);

  /* fire request. print error message in case something went wrong.
   * note: we could use CURLOPT_ERRORBUFFER here instead but the generic msg
   * from curl are enough.
   * TODO: be more pragmatic here and handle this correctly (stats, etc.) */
  curl_easy_perform(handler);
  /*res = curl_easy_perform(handler);
  switch (res) {
   case CURLE_OK:
     break;
   case CURLE_UNSUPPORTED_PROTOCOL:
   case CURLE_COULDNT_RESOLVE_PROXY:
   case CURLE_COULDNT_RESOLVE_HOST:
   case CURLE_REMOTE_ACCESS_DENIED:
   case CURLE_HTTP2:
   case CURLE_HTTP_RETURNED_ERROR:
   case CURLE_WRITE_ERROR:
   case CURLE_OPERATION_TIMEDOUT:
   case CURLE_HTTP_POST_ERROR:
   case CURLE_SSL_CONNECT_ERROR:
   case CURLE_TOO_MANY_REDIRECTS:
   case CURLE_SSL_ENGINE_NOTFOUND:
   case CURLE_SSL_ENGINE_SETFAILED:
   case CURLE_SEND_ERROR:
   case CURLE_RECV_ERROR:
   case CURLE_SSL_CERTPROBLEM:
   case CURLE_SSL_CIPHER:
   case CURLE_PEER_FAILED_VERIFICATION:
   case CURLE_BAD_CONTENT_ENCODING:
   case CURLE_FILESIZE_EXCEEDED:
   case CURLE_USE_SSL_FAILED:
   case CURLE_SEND_FAIL_REWIND:
   case CURLE_SSL_ENGINE_INITFAILED:
   case CURLE_LOGIN_DENIED:
   case CURLE_SSL_CACERT_BADFILE:
   case CURLE_AGAIN:
   case CURLE_SSL_CRL_BADFILE:
   case CURLE_SSL_ISSUER_ERROR:
   case CURLE_NO_CONNECTION_AVAILABLE:
   case CURLE_SSL_PINNEDPUBKEYNOTMATCH:
   case CURLE_HTTP2_STREAM:
#ifndef LAME
   case CURLE_AUTH_ERROR:
   case CURLE_HTTP3:
#endif
     if (num_err < MAX_CURL_ERRORS) {
       if (num_err == 0) {
         SLOG("\n");
       }
       WSLOG("curl error: %s\n", curl_easy_strerror(res));
       ++num_err;
     }
     break;
   default:
     if (num_err < MAX_CURL_ERRORS) {
       if (num_err == 0) {
         SLOG("\n")
       }
       WSLOG("unknown curl error: %s\n", curl_easy_strerror(res));
     }
  }
*/
  return check_ok;
}

