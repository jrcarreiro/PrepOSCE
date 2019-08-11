; Another technique is to write specific values in 2 registers, that will – 
; when an xor operation is performed on the values in these 2 registers, produce the desired value.
[BITS 32]
MOV EAX,0x777777FF
MOV EBX,0x771219CF
XOR EAX,EBX
PUSH EAX
PUSH 0x206d7241
MOV EBX, ESP

MOV EAX,0x777777FF
MOV EDX,0x77191693
XOR EAX,EDX
PUSH EAX
PUSH 0x65726f43
PUSH 0x20656874
PUSH 0x20666f20
PUSH 0x6e616620
PUSH 0x61207962
PUSH 0x2064656e
PUSH 0x7770206e
PUSH 0x65656220
PUSH 0x65766168
PUSH 0x20756f59

MOV ECX,ESP         ;save pointer to "You have been..." in ECX

XOR EAX, EAX
PUSH EAX            ;put parameters on the stack
PUSH EBX
PUSH ECX
PUSH EAX
PUSH EAX

MOV ESI,0x7E4507EA
JMP ESI             ;MessageBoxA

XOR EAX,EAX         ;clean up
PUSH EAX
MOV EAX,0x7c81cafa
JMP EAX             ;ExitProcess(0)