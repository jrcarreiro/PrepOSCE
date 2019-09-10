#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <stdint.h>

int foo(char a, char b, char c, char d){
    int cnt=0;
    printf("a=%c, b=%c, c=%c, d=%c\n", a, b, c, d);
    if(a == 'b')
        cnt++;
    if(b == 'a')
        cnt++;
    if(c == 'd')
        cnt++;
    if(d == '!')
        cnt++;
    if(cnt>=3)
        abort(); //error
    return 0;
}

// fuzz_target.cc 
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if( size < 4 ){
        return 0;
    }
    foo(data[0],data[1],data[2],data[3]);
     return 0;  // Non-zero return values are reserved for future use.
}
