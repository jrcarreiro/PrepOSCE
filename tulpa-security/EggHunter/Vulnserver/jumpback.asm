[BITS 32]
mov eax, esp ; copy value from esp to eax
sub eax, byte 0x40 ; subtract 0x40 (64) from eax
jmp eax ; redirect execution to address in eax