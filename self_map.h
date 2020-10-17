#pragma once
#include <Windows.h>
#include <ntstatus.h>
#include <iostream>
#include <fstream>

#include "colormod.h"

#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

using entry_point_ = BOOL(WINAPI*)(void* hDll, DWORD dwReason, void* pReserved);

class self_map
{
private:
	PBYTE						buffer;
	PBYTE						module_base;
	PIMAGE_DOS_HEADER			dos_header;
	PIMAGE_NT_HEADERS			nt_header;
	PIMAGE_OPTIONAL_HEADER		optional_header;
	PIMAGE_FILE_HEADER			file_header;
public:
	self_map(PBYTE buffer);
	NTSTATUS map();
	void* export_lookup(const char* export_name);
	NTSTATUS free_memory();
};
