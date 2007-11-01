#include <stdio.h>


const unsigned long ROUNDS = 32;
const unsigned long DELTA = 0x9E3779B9;


void encipher(unsigned long *const v,
              const unsigned long * const k) {
  register unsigned long v0 = v[0], v1 = v[1], sum = 0, n = ROUNDS;
  while (n-- > 0) {
    v0 += (v1 << 4 ^ v1 >> 5) + v1 ^ sum + k[sum&3];
    sum += DELTA;
    v1 += (v0 << 4 ^ v0 >> 5) + v0 ^ sum + k[sum>>11 & 3];
  }
  v[0] = v0; v[1] = v1;
}

void decipher(unsigned long *const v,
              const unsigned long * const k) {
  const unsigned long delta = 0x9E3779B9;
  register unsigned long v0 = v[0], v1 = v[1], n = ROUNDS, sum = DELTA*ROUNDS;
  while (n-- > 0) {
    v1 -= (v0 << 4 ^ v0 >> 5) + v0 ^ sum + k[sum>>11 & 3];
    sum -= DELTA;
    v0 -= (v1 << 4 ^ v1 >> 5) + v1 ^ sum + k[sum&3];
  }
  v[0] = v0; v[1] = v1;
}
