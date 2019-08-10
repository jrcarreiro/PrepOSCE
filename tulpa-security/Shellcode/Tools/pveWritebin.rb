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
    shellcode = "\x68\x97\x4C\x80\x7C\xB8" +
    "\x4D\x11\x86\x7C\xFF\xD0"

    puts  "Writing to #{ARGV[0]}"
    File.open("#{ARGV[0]}", 'wb'){|f| f.write(shellcode)}
    puts "Wrote #{shellcode.size} bytes to file"
end