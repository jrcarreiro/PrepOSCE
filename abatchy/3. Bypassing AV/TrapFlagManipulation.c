// The trap flag is used for tracing the program. If this flag is set every instruction will raise “SINGLE_STEP” exception.Trap flag can be manipulated in order thwart tracers. We can manipulate the trap flag with below code
__asm
{
    pushf                   // Push all flags to stack
    mov dword [esp], 0x100  // Set 0x100 to the last flag on the stack
    popf                    // Put back all flags register values
}