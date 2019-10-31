	.586
	.mmx
	.model flat, c
	.code

SignedMinA_ proc
	push ebp
	mov ebp, esp
	mov eax, [ebp+8]
	mov ecx, [ebp+12]

; Determine min(a,b)
	cmp eax, ecx
	jle @F
	mov eax, ecx

; Determine min(a, b, c)
@@:	mov ecx, [ebp+16]
	cmp eax, ecx
	jle @F
	mov eax, ecx

@@:	pop ebp
	ret
SignedMinA_ endp

SignedMaxA_ proc
	push ebp
	mov ebp, esp
	mov eax, [ebp+8]
	mov ecx. [ebp+12]

	cmp eax, ecx
	jge @F
	mov eax, ecx

@@:	mov ecx, [ebp+16]
	cmp eax, ecx
	jge @F
	mov eax, ecx

@@:	pop ebp
	ret
SignedMaxA_ endp

SignedMinB_ proc
	push ebp
	mov ebp, esp
	mov eax, [ebp+8]
	mov ecx, [ebp+12]

	cmp eax, ecx
	cmovg eax, ecx
	mov ecx, [ebp+16]
	cmp eax, ecx
	cmovg	eax, ecx

	pop ebp
	ret
SignedMinB_ endp

SignedMaxB_ proc
	push ebp
	mov ebp, esp
	mov eax, [ebp+8]
	mov ecx, [ebp+12]

	cmp eax, ecx
	cmovl eax, ecx
	mov ecx, [ebp+16]
	cmp eax, ecx
	cmovl eax, ecx

	pop ebp
	ret
SignedMaxB_ endp
	end
