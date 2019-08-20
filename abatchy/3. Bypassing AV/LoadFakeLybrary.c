// This method we will try to load a non existing dll on runtime. Normally when we try to load a non existing dll HISTENCE returns NULL, but some dynamic analysis mechanisms in AV products allows such cases in order to further investigate the execution flow of the program.
bool BypassAV(char const * argv[]) {
    HINSTANCE DLL = LoadLibrary(TEXT("fake.dll"));
    if (DLL != NULL) {
        BypassAV(argv);
    }
}