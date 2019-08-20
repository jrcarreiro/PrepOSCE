// This method will simply check the number of processor cores on the system. Since AV products can’t afford allocating too much resource from host computer we can check the core number in order to determine are we in a sandbox or not. Even some AV products does not support multi core processing so they shouldn’t be able to reserve more than 1 processor core to their sandbox environment.
SYSTEM_INFO SysGuide;
GetSystemInfo(&SysGuide);
int CoreNum = SysGuide.dwNumberOfProcessors;
if (CoreNum < 2) {
    return false;
}