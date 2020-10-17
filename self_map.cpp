#include "self_map.h"

self_map::self_map(PBYTE buffer)
{
	this->buffer = buffer;
	this->module_base = NULL;
	this->dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(this->buffer);
	this->nt_header = reinterpret_cast<PIMAGE_NT_HEADERS>(this->buffer + this->dos_header->e_lfanew);
	this->optional_header = reinterpret_cast<PIMAGE_OPTIONAL_HEADER>(&nt_header->OptionalHeader);
	this->file_header = reinterpret_cast<PIMAGE_FILE_HEADER>(&nt_header->FileHeader);
}

NTSTATUS self_map::map()
{
	/* Check file signature */
	if (this->dos_header->e_magic != 0x5A4D)
	{
		std::cout << ERROR << "Invalid DOS signature" << std::endl;
		return STATUS_UNSUCCESSFUL;
	}

	/* Check platform */
	if (this->file_header->Machine != IMAGE_FILE_MACHINE_AMD64)
	{
		std::cout << ERROR << "Invalid arch" << std::endl;
		return STATUS_UNSUCCESSFUL;
	}

	/* Allocate memory */
	this->module_base = reinterpret_cast<PBYTE>(VirtualAlloc(NULL, this->optional_header->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	if (!this->module_base)
	{
		std::cout << ERROR << "Failed to alloc memory (" << GetLastError() << ")" << std::endl;
		return STATUS_UNSUCCESSFUL;
	}

	std::cout << SUCCESS << "Allocated 0x" << std::uppercase << std::hex << this->optional_header->SizeOfImage << " bytes at 0x" << std::uppercase << std::hex << (uintptr_t)this->module_base << std::endl;

	/* Map header */
	if (!RtlCopyMemory(this->module_base, this->buffer, this->optional_header->SizeOfHeaders))
	{
		std::cout << ERROR << "Failed to map header (" << GetLastError() << ")" << std::endl;
		return STATUS_UNSUCCESSFUL;
	}

	std::cout << SUCCESS << "Mapped header" << std::endl;

	/* Map sections */
	PIMAGE_SECTION_HEADER section_header = IMAGE_FIRST_SECTION(this->nt_header);
	for (size_t i = 0; i != this->file_header->NumberOfSections; ++i, ++section_header)
	{
		if (!section_header->SizeOfRawData)
			continue;

		if (!RtlCopyMemory(this->module_base + section_header->VirtualAddress, this->buffer + section_header->PointerToRawData, section_header->SizeOfRawData))
		{
			std::cout << ERROR << "Failed to map " << section_header->Name << " section (" << GetLastError() << ")" << std::endl;
			return STATUS_UNSUCCESSFUL;
		}

		std::cout << SUCCESS << "Mapped " << section_header->Name << " section" << std::endl;
	}

	/* Fix relocations */
	PIMAGE_BASE_RELOCATION base_relocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(this->module_base + this->optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	while (base_relocation->VirtualAddress)
	{
		PWORD relative_info = reinterpret_cast<PWORD>(base_relocation + 1);

		for (UINT i = 0; i != (base_relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD); ++i, ++relative_info)
		{
			if (RELOC_FLAG64(*relative_info))
			{
				UINT_PTR* patch = reinterpret_cast<UINT_PTR*>(this->module_base + base_relocation->VirtualAddress + ((*relative_info) & 0xFFF));
				*patch += reinterpret_cast<UINT_PTR>(this->module_base - this->optional_header->ImageBase);
			}
		}

		base_relocation = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(base_relocation) + base_relocation->SizeOfBlock);
	}

	/* Fix imports */
	if (this->optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
	{
		PIMAGE_IMPORT_DESCRIPTOR import_descriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(this->module_base + this->optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (import_descriptor->Name)
		{
			HINSTANCE library_address = LoadLibrary(reinterpret_cast<char*>(this->module_base + import_descriptor->Name));

			ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(this->module_base + import_descriptor->OriginalFirstThunk);
			ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(this->module_base + import_descriptor->FirstThunk);

			if (!pThunkRef)
				pThunkRef = pFuncRef;

			for (; *pThunkRef; ++pThunkRef, ++pFuncRef)
			{
				if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef))
				{
					*pFuncRef = (ULONG_PTR)GetProcAddress(library_address, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
				}
				else
				{
					PIMAGE_IMPORT_BY_NAME import = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(this->module_base + (*pThunkRef));
					*pFuncRef = (ULONG_PTR)GetProcAddress(library_address, import->Name);
				}
			}

			++import_descriptor;
		}
	}

	/* Callbacks */
	if (this->optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
	{
		PIMAGE_TLS_DIRECTORY pTLS = reinterpret_cast<PIMAGE_TLS_DIRECTORY>(this->module_base + this->optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		PIMAGE_TLS_CALLBACK* callback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);

		for (; callback && *callback; ++callback)
		{
			(*callback)(this->module_base, DLL_PROCESS_ATTACH, nullptr);
		}
	}

	/* Call entry point */
	reinterpret_cast<entry_point_>(this->module_base + this->optional_header->AddressOfEntryPoint)(this->module_base, DLL_PROCESS_ATTACH, nullptr);

	std::cout << SUCCESS << "Mapped!" << std::endl;
	return STATUS_SUCCESS;
}

void* self_map::export_lookup(const char* export_name)
{
	const auto export_directory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(this->module_base + this->optional_header->DataDirectory[0].VirtualAddress);
	const auto export_functions = reinterpret_cast<std::uint32_t*>(this->module_base + export_directory->AddressOfFunctions);
	const auto export_names = reinterpret_cast<std::uint32_t*>(this->module_base + export_directory->AddressOfNames);

	for (int i = 0; i < export_directory->NumberOfNames; i++)
	{
		const auto current_export_name = reinterpret_cast<const char*>(this->module_base + export_names[i]);

		if (std::strcmp(current_export_name, export_name))
			continue;

		return reinterpret_cast<void*>(this->module_base + export_functions[i]);
	}

	return NULL;
}

NTSTATUS self_map::free_memory()
{
	std::cout << INFO << "Freeing memory" << std::endl;

	if (this->buffer)
		free((void*)this->buffer);

	if (!VirtualFree(this->module_base, NULL, MEM_RELEASE))
	{
		std::cout << ERROR << "VirtualFree failed (" << GetLastError() << ")" << std::endl;
		return STATUS_UNSUCCESSFUL;
	}

	std::cout << SUCCESS << "Successfully freed memory" << std::endl;
	return STATUS_SUCCESS;
}
