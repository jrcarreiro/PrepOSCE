; ----------------------------------------------------------------------------------------
; Writes "Hello, World" to the console using only system calls. Runs on 64-bit Linux only.
; To assemble and run:
;
;     nasm -f elf32 hello32.asm && ld hello32.o && ./a.out
; ----------------------------------------------------------------------------------------

global _start

section .text
_start:
    mov eax, 0x4
    mov ebx, 0x1
    mov ecx, message
    mov edx, mlen
    int 0x80

    mov eax, 0x1
    mov ebx, 0x5
    int 0x80

section .data
    message:    db  "Hello, World", 10
    mlen equ $-message