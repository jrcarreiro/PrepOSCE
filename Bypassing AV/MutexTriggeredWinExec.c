// This method is very promising because of its simplicity, we create a condition for checking whether a certain mutex object already exists on the system or not.
// If “CreateMutex” function does not return already exists error we execute the malware binary again, since most of the AV products don’t let programs witch are dynamically analyzing to start new processes  or access the files outside the AV sandbox, when the already exist error occurs execution of the decrypt function may start. There are much more creative ways of mutex usage in anti detection.
HANDLE AmberMutex = CreateMutex(NULL, TRUE, "FakeMutex");
if(GetLastError() != ERROR_ALREADY_EXISTS){
    WinExec(argv[0],0);
}