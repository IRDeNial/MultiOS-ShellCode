#include <Windows.h>
#include <NTSecAPI.h>
#include <TlHelp32.h>
#include <vector>

namespace Shell {

	// This function is so common, I don't even know where it came from or who to credit
	// So lets just say I didn't write it and just copied it from somewhere.
	bool bDataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask)	{
		for (; *szMask; ++szMask, ++pData, ++bMask){
			if (*szMask == 'x' && *pData != *bMask)
				return false;
		}
		return (*szMask) == NULL;
	}

	// This one too.
	DWORD dwFindPattern(DWORD dwAddress, DWORD dwLen, BYTE *bMask, char * szMask) {
		for (DWORD i = 0; i<dwLen; i++){
			if (bDataCompare((BYTE*)(dwAddress + i), bMask, szMask))
				return (DWORD)(dwAddress + i);
		}
		return NULL;
	}

	// Was used in a different program, QuikHop.
	DWORD FixAddr(BYTE* shellcode, DWORD newAddr, PVOID AllocBase, DWORD dwLen = 1024) {
		DWORD fixAddr = dwFindPattern((DWORD)&shellcode[0], dwLen, (BYTE*)"\xDE\xAD\xC0\xDE", "xxxx");
		DWORD realOffset = (fixAddr - (DWORD)&shellcode[0]) + (DWORD)AllocBase;
		if (fixAddr) {
			*(DWORD *)fixAddr = newAddr;
			return realOffset;
		}
		return NULL;
	}
}

int main() {
	// This is the shell code.
	// Base taken from here: http://projectshellcode.com/node/19
	// Replaced any function calls with \xDE\xAD\xC0\xDE for future use
	// \x48\x65\x6c\x6c\x6f\x00 = "Hello" for message box
	BYTE shellCode[] =
		"\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xeb\x2a\x59\xbb"
		"\xDE\xAD\xC0\xDE\x51\xff\xd3\xeb\x2f\x59\x51\x50"
		"\xbb\xDE\xAD\xC0\xDE\xff\xd3\xeb\x34\x59\x31\xd2"
		"\x52\x51\x51\x52\xff\xd0\x31\xd2\x50\xb8\xDE\xAD"
		"\xC0\xDE\xff\xd0\xe8\xd1\xff\xff\xff\x75\x73\x65"
		"\x72\x33\x32\x2e\x64\x6c\x6c\x00\xe8\xcc\xff\xff"
		"\xff\x4d\x65\x73\x73\x61\x67\x65\x42\x6f\x78\x41"
		"\x00\xe8\xc7\xff\xff\xff\x48\x65\x6c\x6c\x6f\x00";

	// Allocate memory for shell code to execute in
	void *func = VirtualAlloc(0, sizeof shellCode, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	
	// Those \xDE\xAD\xC0\xDE parts in the shell code?
	// Lets replace those with actual function calls.
	// Replacements go from the first find to last find, so be sure you're doing it in the right order.
	Shell::FixAddr(&shellCode[0], (DWORD)GetProcAddress(LoadLibraryA("Kernel32.dll"), "LoadLibraryA"), shellCode);
	Shell::FixAddr(&shellCode[0], (DWORD)GetProcAddress(LoadLibraryA("Kernel32.dll"), "GetProcAddress"), shellCode);
	Shell::FixAddr(&shellCode[0], (DWORD)GetProcAddress(LoadLibraryA("Kernel32.dll"), "ExitProcess"), shellCode);

	// Just print it out to be sure.  Debug purposes, obviously.
	printf("Shell Code: ");
	for (int i = 0; i < sizeof shellCode; ++i)
		printf("\\x%2x", shellCode[i]);
	putchar('\n');

	// Print the address of the shell code for lulz
	printf("Shell Code Address: %p", &shellCode);

	// Final pause before execution.
	getchar();

	try {
		// Copy the shell code into the previous allocated memory
		memcpy(func, shellCode, sizeof shellCode);
		// And execute
		((void(*)())func)();
	}
	catch (char *e) {
		// This probably doesn't even work, so IDK why I put this here.
		// Habit I guess?  Who knows.
		printf("Exception Caught: %s\n", e);
	};

	// DIE IF YOU HAVEN'T ALREADY!
	return 0;
}