// When the programs memory starts to grow on runtime eventually AV scanners will end the scan for the sake of not to spend too much time on a file, this method can be used multiple times. This is a very primitive and old technique but it still bypasses good amount of scanners.
char * Memdmp = NULL;
Memdmp = (char *)malloc(100000000);
if (Memdmp != NULL) {
    memset (Memdmp, 00, 100000000);
    free(Memdmp);
}