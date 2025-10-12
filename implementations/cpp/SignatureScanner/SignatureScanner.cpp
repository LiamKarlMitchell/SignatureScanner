// SignatureScanner.cpp : Defines the functions for the static library.

#include "pch.h"
#include "framework.h"
#include "SignatureScanner.h"

void signature_scanner::proctect_claim(PVOID address, SIZE_T size)
{
	// Add a protection
	protections.push(new MemPageProtection(address, size));
}

void signature_scanner::protect_unclaim()
{
	protections.pop();
}

signature_scanner::signature_scanner()
{
	// SYSTEM_INFO info;
	// GetSystemInfo(&info);
	// this->BaseAddress = (uintptr_t)info.lpMinimumApplicationAddress;

	// Could be injected earlier than expected

	while (!(this->BaseAddress = (uintptr_t)GetModuleHandle(NULL)))
		Sleep(100);

	// Getting size of image

	MODULEINFO modinfo;

	while (!GetModuleInformation(GetCurrentProcess(), GetModuleHandle(NULL), &modinfo, sizeof(MODULEINFO)))
		Sleep(100);

	this->ModuleSize = modinfo.SizeOfImage;

	// Wait for the application to finish loading
	// Hook Virtual Protect
	// If its called from a gameguard module then bullshit the reply so it thinks memory access as changed

	// BOOL WINAPI VirtualProtect(
	//   LPVOID lpAddress,
	//   SIZE_T dwSize,
	//   DWORD flNewProtect,
	//   PDWORD lpflOldProtect
	//);

	// Log.Write("Something is trying to change memory protection of %08X size of %u",lpAddress,dwSize);
	//

	MEMORY_BASIC_INFORMATION meminfo;

	while (true)
	{
		if (VirtualQuery((void *)this->BaseAddress, &meminfo, sizeof(MEMORY_BASIC_INFORMATION)))
			if (!(meminfo.Protect & PAGE_EXECUTE_WRITECOPY))
				break;

		Sleep(100);
	}
}

uintptr_t signature_scanner::search_text(const char *string, short offset, bool fromStart, uintptr_t startAddress)
{
	size_t origionallength = strlen(string);
	size_t hexstringlength = (origionallength * 2) + 1;
	char *hexstring = new char[hexstringlength];

	size_t b = 0;
	for (size_t i = 0; i < origionallength; i++)
	{
		if (string[i] == '?')
		{
			hexstring[b] = '?';
			hexstring[b + 1] = '?';
		}
		else
		{
			sprintf_s(&hexstring[b], hexstringlength - b, "%02X", (unsigned char)string[i]);
		}
		b += 2;
	}

	uintptr_t address = search(hexstring, offset, fromStart, startAddress);
	delete[] hexstring;
	return address;
}

// Fixed it up so that it dosnt try to cast whats at the location as an unsigned long* rather it just passes the pointer back.
// Unless we have XXXX marking the address we want casted into the pointer :).
uintptr_t signature_scanner::search(const char *string, short offset, bool fromStart, uintptr_t startAddress, uintptr_t *nextAddress)
{
	size_t p_length = strlen(string); // Pattern's length

	if (p_length % 2 != 0 || p_length < 2 || !this->BaseAddress || !this->ModuleSize)
		return 0; // Invalid operation

	size_t length = p_length / 2; // Number of bytes

	// The buffer is storing the real bytes' values after parsing the string
	unsigned char *buffer = new unsigned char[length];
	SecureZeroMemory(buffer, length);

	// Copy of string

	char *pattern = new char[p_length + 1]; // +1 for the null terminated string
	ZeroMemory(pattern, p_length + 1);
	strcpy_s(pattern, p_length + 1, string);
	_strupr_s(pattern, p_length + 1);

	// Set vars

	unsigned char f_byte;
	unsigned char s_byte;

	// Parsing of string

	for (size_t z = 0; z < length; z++)
	{
		// Should I toupper these?
		f_byte = pattern[z * 2];	   // First byte
		s_byte = pattern[(z * 2) + 1]; // Second byte

		if (((f_byte <= 'F' && f_byte >= 'A') || (f_byte <= '9' && f_byte >= '0')) && ((s_byte <= 'F' && s_byte >= 'A') || (s_byte <= '9' && s_byte >= '0')))
		{
			if (f_byte <= '9')
				buffer[z] += f_byte - '0';
			else
				buffer[z] += f_byte - 'A' + 10;
			buffer[z] *= 16;
			if (s_byte <= '9')
				buffer[z] += s_byte - '0';
			else
				buffer[z] += s_byte - 'A' + 10;
		}
		else if (f_byte == 'X' || s_byte == 'X')
			buffer[z] = 'X';
		else
			buffer[z] = '?'; // Wildcard
	}

	// Remove buffer

	delete[] pattern;

	// Start searching

	size_t x;
	uintptr_t i = this->BaseAddress;
	if (startAddress != 0)
		i = startAddress;
	MEMORY_BASIC_INFORMATION meminfo;
	uintptr_t EOR;

	while (i < this->ModuleSize)
	{
		VirtualQuery((void *)i, &meminfo, sizeof(MEMORY_BASIC_INFORMATION));

		DWORD dwPage_Protection = 0;
		// Set page protection to readwrite
		VirtualProtect((PVOID)meminfo.BaseAddress, meminfo.RegionSize, PAGE_EXECUTE_READWRITE, &dwPage_Protection);

		// FUCK IT SCAN ALL MEMORY
		// if (!(meminfo.Protect &PAGE_EXECUTE_READWRITE))// Good for AVA for now
		// if (!(meminfo.Protect &PAGE_READWRITE))
		//{// !(meminfo.Protect &(PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) || !(meminfo.State &MEM_COMMIT)
		//	i += meminfo.RegionSize;
		//	continue;
		//}

		EOR = i + meminfo.RegionSize;

		for (; i < EOR; i++)
		{
			for (x = 0; x < length; x++)
				if (buffer[x] != ((unsigned char *)(void *)i)[x] && buffer[x] != '?' && buffer[x] != 'X')
					break;

			if (x == length)
			{
				delete[] buffer;
				const char *s_offset = strstr(string, "X");

				if (nextAddress != NULL)
				{
					*nextAddress = i + 1;
				}

				if (s_offset != NULL)
				{
					// Set page protection back to what it was origionaly
					DWORD dwOldProtect;
					VirtualProtect((PVOID)meminfo.BaseAddress, meminfo.RegionSize, dwPage_Protection, &dwOldProtect);
					return (*(uintptr_t *)&((unsigned char *)(void *)i)[length - strlen(s_offset) / 2]) + offset;
					// return (unsigned long)i+ (length-strlen(s_offset)/2);
				}
				else
				{
					if (fromStart)
					{
						// Set page protection back to what it was origionaly
						DWORD dwOldProtect;
						VirtualProtect((PVOID)meminfo.BaseAddress, meminfo.RegionSize, dwPage_Protection, &dwOldProtect);
						return (uintptr_t)i + offset;
						// return *(unsigned long*)&((unsigned char*)i)[offset];
					}
					else
					{
						// Set page protection back to what it was origionaly
						DWORD dwOldProtect;
						VirtualProtect((PVOID)meminfo.BaseAddress, meminfo.RegionSize, dwPage_Protection, &dwOldProtect);
						// return *(unsigned long*)&((unsigned char*)i)[length + offset];
						return (uintptr_t)i + length + offset;
					}
				}
			}
		}

		// Set page protection back to what it was origionaly
		DWORD dwOldProtect;
		VirtualProtect((PVOID)meminfo.BaseAddress, meminfo.RegionSize, dwPage_Protection, &dwOldProtect);
	}

	// Didn't find anything

	delete[] buffer;
	return 0;
}

bool signature_scanner::find_all(vector<uintptr_t> &found, const char *string, short offset, bool fromStart, uintptr_t startAddress)
{
	vector<uintptr_t>::size_type size = found.size();

	uintptr_t address = startAddress;
	uintptr_t nextAddress;
	nextAddress = startAddress;

	while (address = search(string, offset, fromStart, nextAddress, &nextAddress))
	{
		found.push_back(address);
	}

	return size != found.size();
}