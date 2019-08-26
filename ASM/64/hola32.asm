global  main
extern  puts

section .text

_main:
    mov     edi, message
    call    puts
    ret
message:
    db      "Hola, mundo", 0