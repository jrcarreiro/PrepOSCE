; arwin kernel32.dll LoadLibraryA
; arwin kernel32.dll GetProcAddress
; arwin kernel32.dll ExitProcess
; asm -f elf msgbox.asm; ld -o msgbox msgbox.o; objdump -d msgbox
[SECTION .text]

global _start

_start:
	;eax holds return value
	;ebx will hold function addresses
	;ecx will hold string pointers
	;edx will hold NULL

    xor eax, eax
    xor ebx, ebx
    xor ecx, ecx
    xor edx, edx

    jmp short GetLibrary

LibraryReturn:
    pop ecx
    mov [ecx + 10], dl
    mov ebx, 0x77e7d961
    push ecx
    call ebx

    jmp short FunctionName

FunctionReturn:
    pop ecx
    xor edx, edx
    mov [ecx + 11], dl
    push ecx
    push eax
    mov ebx, 0x77e7b332
    call ebx

    jmp short Message

MessageReturn:
    pop ecx
    xor edx, edx
    mov [ecx + 3], dl

    xor edx, edx

    push edx
    push ecx
    push ecx
    push edx

    call eax

ender:
    xor edx, edx
    push eax
    mov eax, 0x77e798fd
    call eax

GetLibrary:
	call LibraryReturn
	db 'user32.dllN'
FunctionName
	call FunctionReturn
	db 'MessageBoxAN'
Message
	call MessageReturn
	db 'OpaSopa'