#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int main() {
    uint64_t *ptr1, *ptr2, *fakechunk, *ptr3, *ptr4;
    malloc(0x10);
    ptr1 = malloc(0x100);
    ptr2 = malloc(0x80);
    ptr3 = malloc(0x200);
    // ptr4 = malloc(0x80);

    fakechunk = &ptr1[8];
    fakechunk[-1] = 0xd1;
    fakechunk[0] = &fakechunk[-1];
    fakechunk[1] = &fakechunk[0];
    fakechunk[2] = &fakechunk[-2];
    ptr2[-1] = 0x90;
    ptr2[-2] = 0xd0;

    free(ptr2);
    // free(ptr1);
}