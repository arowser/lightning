#include <string.h>
void
__explicit_bzero_chk (void *dst, size_t len, size_t dstlen)
{
  memset (dst, '\0', len);
  asm volatile ("" ::: "memory");
}
