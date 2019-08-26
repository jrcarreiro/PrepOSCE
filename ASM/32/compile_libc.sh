nasm -f elf32 -o $1.o $1.asm
gcc -o $1 $1.o