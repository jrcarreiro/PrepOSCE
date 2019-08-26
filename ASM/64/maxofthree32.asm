global maxofthree
section .text

maxofthree:
    mov eax, edi
    cmp eax, esi
    cmovl eax, esi
    cmp eax, edx
    cmovl eax, edx
    ret