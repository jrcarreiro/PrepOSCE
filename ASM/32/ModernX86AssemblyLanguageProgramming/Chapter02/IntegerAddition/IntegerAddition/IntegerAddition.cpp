// IntegerAddition.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <tchar.h>

extern "C" char GlChar = 10; //compiler to use C-style names instead of C++ decorated names when generating public symbols for use by the linker. 
extern "C" short GlShort = 20; //compiler to use C-style names instead of C++ decorated names when generating public symbols for use by the linker. 
extern "C" int GlInt = 30; //compiler to use C-style names instead of C++ decorated names when generating public symbols for use by the linker. 
extern "C" long long GlLongLong = 0x000000000FFFFFFFE; //compiler to use C-style names instead of C++ decorated names when generating public symbols for use by the linker. 

extern "C" void IntegerAddition_(char a, short b, int c, long long d);

int _tmain(int argc, _TCHAR* argv[])
{
	printf("Before GlChar:     %d\n", GlChar);
	printf("       GlShort:    %d\n", GlShort);
	printf("       GlInt:      %d\n", GlInt);
	printf("       GlLongLong: %lld\n", GlLongLong);
	printf("\n");

	IntegerAddition_(3, 5, -37, 11);

	printf("After  GlChar:     %d\n", GlChar);
	printf("       GlShort:    %d\n", GlShort);
	printf("       GlInt:      %d\n", GlInt);
	printf("       GlLongLong: %lld\n", GlLongLong);
	return 0;
}