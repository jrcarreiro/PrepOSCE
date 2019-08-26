#!/usr/bin/env ruby

asm = ARGV[0]
system ("nasm -f elf32 -o #{asm}.o #{asm}.asm")
puts "File output #{asm}.o was created! " if $?.success? == true

system ("ld -o #{asm} #{asm}.o ")
puts "File output #{asm} was created! " if $?.success? == true