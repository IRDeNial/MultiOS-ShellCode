#include <Windows.h>
#include <NTSecAPI.h>
#include <TlHelp32.h>
#include <stdio.h>

#ifndef SHELL_HEADER
#define SHELL_HEADER

namespace Shell {
	// This function is so common, I don't even know where it came from or who to credit
	// So lets just say I didn't write it and just copied it from somewhere.
	bool bDataCompare(const BYTE *, const BYTE *, const char *);

	// This one too.
	DWORD dwFindPattern(DWORD, DWORD, BYTE *, char *);

	// Was used in a different program, QuikHop.
	DWORD FixAddr(BYTE *, DWORD, PVOID, DWORD = 1024);
}

#endif