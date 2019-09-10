#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

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
}

int main(int argc, char * argv[]){
    FILE *f;
    char a, b, c, d;
    if( argc != 2)
    {
        printf("bad args, need valid file name\n");
        exit(-1);
    }
    f = fopen(argv[1], "r");
    if( f )
    {
        fread(&a, 1, 1, f);
        fread(&b, 1, 1, f);
        fread(&c, 1, 1, f);
        fread(&d, 1, 1, f);
        foo(a, b, c, d);
    }
}