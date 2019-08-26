;arwin kernel32.dll Sleep
;asm -f elf sleep.asm; ld -o sleep sleep.o; objdump -d sleep
[SECTION .text]

global _start

_start:
    xor eax, eax
    mov ebx, 0x77e61bea ;address of Sleep
    mov ax, 5000
    push eax
    call ebx