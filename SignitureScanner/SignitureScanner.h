// Something I released too. Its a Signature scanning libary.
// I did a youtube video showing how to use it here: https://www.youtube.com/watch?v=WmHDQzfELxk

#ifndef __SignitureScanner_H
#define __SignitureScanner_H

#include "stdafx.h"

// Origional code by Jabberwo0ck on mpgh.net
// http://www.mpgh.net/forum/284-alliance-valiant-arms-ava-coding-source-code/505474-c-signature-scanner.html

// Usage: DWORD_PTR address = signature_scanner->search("3AB2DFAB????????3FBACD300200A1XXXXXXXXB1C4DA");
// X is the address
// ? is a wildcard
#define vector_unsigned_long vector<unsigned long>

class MemPageProtection
{
private:
	PVOID Address;
    SIZE_T Size;
    DWORD Page_Protection;
public:
    MemPageProtection(PVOID address,SIZE_T size)
	{
		if (size==0)
		{
			MEMORY_BASIC_INFORMATION meminfo;
			VirtualQuery(address, &meminfo, sizeof(MEMORY_BASIC_INFORMATION));
			
			Address = meminfo.BaseAddress;
			Size = meminfo.RegionSize;
		}
		else
		{
			Address = address;
			Size = size;
		}

		// Set the protection to EXECUTE_READWRITE
		VirtualProtect(Address, Size, PAGE_EXECUTE_READWRITE, &Page_Protection);
	}
    ~MemPageProtection()
	{
		// Restore protection
		VirtualProtect(Address, Size, Page_Protection, NULL);
	}
};

class signature_scanner
{
private:
	unsigned long BaseAddress;
	unsigned long ModuleSize;

	stack<MemPageProtection*> protections;

public:
	void proctect_claim(PVOID address,SIZE_T size=0);
	void protect_unclaim();
	signature_scanner();
	unsigned long search_text(const char* string, short offset=0, bool fromStart=true,unsigned long startAddress=0);
	unsigned long search(const char* string, short offset=0, bool fromStart=true,unsigned long startAddress=0,unsigned long* nextAddress=0);
	bool find_all(vector_unsigned_long& found,const char* string, short offset=0, bool fromStart=true,unsigned long startAddress=0);
};

#endif