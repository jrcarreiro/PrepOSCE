// In this method we will be exploiting the time deadline of AV products. In most cases AV scanners are being designed for end user, they need to be user friendly and suitable for daily usage this means they can’t spend too much time for scanning files they need to scan files as quickly as possible. At first malware developers used “sleep()” function for waiting until the scan complete, but nowadays this trick almost never works, every AV product skips the sleep function when they encountered one. We will use this against them , below code uses a win API function called “GetThickCount()” this function “Retrieves the number of milliseconds that have elapsed since the system was started, up to 49.7 days.” we will use it to get the time passed since OS booted, then try to sleep 1 second, after sleep function we will check weather sleep function is skipped or not by comparing the two GetTickCout() value.
int Tick = GetTickCout();
Sleep(1000);
int Tac = GetTickCout();
if ((Tac - Tick) < 1000) {
    return false;
}