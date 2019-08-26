global _start

section .text
_start:

    xor eax, eax
    mov al, 1
    xor ebx, ebx
    mov bl, 10
    int 0x80