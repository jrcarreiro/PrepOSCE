char code[] =
"\x31\xc0\x89\xe5\x68\x6c\x61\x6e"
"\xff\x88\x45\xff\x68\x43\x6f\x72"
"\x65\x89\xe3\x68\x61\x6e\x20\xff"
"\x88\x45\xf7\x68\x6f\x72\x65\x6c"
"\x68\x62\x79\x20\x43\x68\x6e\x65"
"\x64\x20\x68\x6e\x20\x70\x77\x68"
"\x20\x62\x65\x65\x68\x68\x61\x76"
"\x65\x68\x59\x6f\x75\x20\x89\xe1"
"\x50\x53\x51\x50\x50\xbe\xea\x07"
"\x45\x7e\xff\xe6\x31\xc0\x50\xb8"
"\x12\xcb\x81\x7c\xff\xe0";

int main(int argc, char **argv)
{
   int (*func)();
   func = (int (*)()) code;
   (int)(*func)(); // call to [ebp-4]
}