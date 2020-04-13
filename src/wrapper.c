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
* wrapper.c                                                                    *
*                                                                              *
* AUTHOR                                                                       *
* noptrix@nullsecurity.net                                                     *
*                                                                              *
*******************************************************************************/


/* sys includes */


/* own includes */
#include "wrapper.h"
#include "error.h"


/* realloc() wrapper */
void *xrealloc(void *ptr, size_t size)
{
  void *buff;

  if ((buff = realloc(ptr, size)) == NULL) {
    err(E_SYS);
  }

  return buff;
}


/* calloc() wrapper */
void *xcalloc(size_t nmemb, size_t size)
{
  void *buff;

  if ((buff = calloc(nmemb, size)) == NULL) {
    err(E_SYS);
  }

  return buff;
}


/* malloc() wrapper */
void *xmalloc(size_t size)
{
  void *buff;

  if ((buff = malloc(size)) == NULL) {
    err(E_SYS);
  }

  return buff;
}


/* memset() wrapper */
void *xmemset(void *s, int c, size_t n)
{
  if (!(s = memset(s, c, n))) {
    err(E_SYS);
  }

  return s;
}


/* memcpy() wrapper */
void *xmemcpy(void *dest, const void *src, size_t n)
{
  dest = memcpy(dest, src, n);

  if (dest == NULL) {
    err(E_SYS);
  }

  return dest;
}

