char code[] = "PUT SHELLCODE HERE";

int main(int argc, char **argv)
{
   int (*func)();
   func = (int (*)()) code;
   (int)(*func)(); // call to [ebp-4]
}