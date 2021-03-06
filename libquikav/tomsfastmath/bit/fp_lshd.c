/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@gmail.com
 */
#include "bignum_fast.h"

void fp_lshd(fp_int *a, int x)
{
   int y;

   /* move up and truncate as required */
   y = MIN(a->used + x - 1, (int)(FP_SIZE-1));

   /* store new size */
   a->used = y + 1;

   /* move digits */
   for (; y >= x; y--) {
       a->dp[y] = a->dp[y-x];
   }
 
   /* zero lower digits */
   for (; y >= 0; y--) {
       a->dp[y] = 0;
   }

   /* quikp digits */
   fp_quikp(a);
}

/* $Source: /cvs/libtom/tomsfastmath/src/bit/fp_lshd.c,v $ */
/* $Revision: 1.1 $ */
/* $Date: 2006/12/31 21:25:53 $ */
