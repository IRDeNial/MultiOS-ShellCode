#include "Shell.h"

bool Shell::bDataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask)	{
	for (; *szMask; ++szMask, ++pData, ++bMask){
		if (*szMask == 'x' && *pData != *bMask)
			return false;
	}
	return (*szMask) == NULL;
}

// This one too.
DWORD Shell::dwFindPattern(DWORD dwAddress, DWORD dwLen, BYTE *bMask, char * szMask) {
	for (DWORD i = 0; i<dwLen; i++){
		if (bDataCompare((BYTE*)(dwAddress + i), bMask, szMask))
			return (DWORD)(dwAddress + i);
	}
	return NULL;
}

// Was used in a different program, QuikHop.
DWORD Shell::FixAddr(BYTE* shellcode, DWORD newAddr, PVOID AllocBase, DWORD dwLen) {
	DWORD fixAddr = dwFindPattern((DWORD)&shellcode[0], dwLen, (BYTE*)"\xDE\xAD\xC0\xDE", "xxxx");
	DWORD realOffset = (fixAddr - (DWORD)&shellcode[0]) + (DWORD)AllocBase;
	if (fixAddr) {
		*(DWORD *)fixAddr = newAddr;
		return realOffset;
	}
	return NULL;
}