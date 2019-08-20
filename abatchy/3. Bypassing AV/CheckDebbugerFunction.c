// bool WINAPI IsDebuggerPresent(void);
// __asm
// {
// CheckDebugger:
//   PUSH EAX                    // Save the EAX value to stack
//   MOV EAX, [FS:0x30]          // Get PEB structure address
//   MOV EAX, [EAX+0x02]         // Get being debugged byte
//   TEST EAX, EAX               // Check if being debuged byte is set
//   JNE CheckDebugger           // If debugger present check again
//   POP EAX                     // Put back the EAX value
// }
//Obfuscate code below
__asm
{
    CheckDebugger:
    push eax
    mov eax, dword ptr fs:[0x18]
    __asm
    {
        push eax
        xor eax, eax
        jz J
        __asm __emit(0xea)
    J:
        pop eax
    }
    mov eax, dword ptr[eax+0x30]
    __asm
    {
        push eax
        xor eax, eax
        jz J2
        __asm __emit(0xea)
    J2:
        pop eax
    }
    cmp byte ptr[eax+2], 0
    __asm
    {
        push eax
        xor eax, eax
        jz J3
        __asm __emit(0xea)
    J3:
        pop eax
    }
    jne CheckDebugger
    pop eax
}
