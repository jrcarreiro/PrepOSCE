#include <stdlib.h>
#include <stdio.h> 
#include <string.h>

char static_buffer1[16]; 
char static_buffer2[16]; 
void (*fn)(int); 
int main(int argc, char *argv[]){
    char stack_buffer1[16];
    char stack_buffer2[16];
    char *heap_buffer1 = (char *) malloc(16);
    char *heap_buffer2 = (char *) malloc(16);
    char *dummy;
    fn = exit;
if(argc < 3){
    printf("Need 2 arguments\n");
    exit(-1);
    }
int x = atoi(argv[1]);
switch(x){
    case 0:
        // Stack overflow
        strcpy(stack_buffer2, argv[2]);
        break;
    case 1:
        // Heap overflow
        strcpy(heap_buffer1, argv[2]);
        break;
    case 2:
        // Static overflow
        strcpy(static_buffer2, argv[2]);
        break;
    case 3:
        // wild write
        heap_buffer1[atoi(argv[2])] = 0;
        break;
    case 4:
        // memory exhaustion (and buffer overflow)
        dummy = (char *) malloc(atoi(argv[2]));
        memset(dummy, 0x41, atoi(argv[2]));
        strcpy(dummy, "hello");
        break;
} 
free(heap_buffer2);
free(heap_buffer1);
fn(0);
}
