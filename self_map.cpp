#include "self_map.h"

self_map::self_map(PBYTE buffer)
{
	this->process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());;
	this->buffer = buffer;
	this->module_base = NULL;
	this->dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(this->buffer);
	this->nt_header = reinterpret_cast<PIMAGE_NT_HEADERS>(this->buffer + dos_header->e_lfanew);
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

	/* Open process */
	if (!this->process_handle)
	{
		std::cout << ERROR << "Cannot open process" << std::endl;
		return STATUS_UNSUCCESSFUL;
	}

	/* Check platform */
	if (this->file_header->Machine != IMAGE_FILE_MACHINE_AMD64)
	{
		std::cout << ERROR << "Invalid arch" << std::endl;
		return STATUS_UNSUCCESSFUL;
	}

	/* Allocate buffer in target process */
	this->module_base = reinterpret_cast<PBYTE>(VirtualAllocEx(this->process_handle, nullptr, this->optional_header->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	if (!this->module_base)
	{
		std::cout << ERROR << "Failed to alloc memory (" << GetLastError() << ")" << std::endl;
		return STATUS_UNSUCCESSFUL;
	}

	std::cout << SUCCESS << "Allocated 0x" << std::uppercase << std::hex << this->optional_header->SizeOfImage << " bytes at 0x" << std::uppercase << std::hex << (uintptr_t)this->module_base << std::endl;

	/* Write first 0x1000 bytes (header) */
	if (!WriteProcessMemory(this->process_handle, this->module_base, this->buffer, 0x1000, nullptr))
	{
		std::cout << ERROR << "Failed to write header (" << GetLastError() << ")" << std::endl;
		return STATUS_UNSUCCESSFUL;
	}

	/* Iterate and map each section */
	PIMAGE_SECTION_HEADER section_header = IMAGE_FIRST_SECTION(this->nt_header);
	for (UINT i = 0; i != this->file_header->NumberOfSections; ++i, ++section_header)
	{
		if (!section_header->SizeOfRawData)
			continue;

		/* Map section */
		if (WriteProcessMemory(process_handle, this->module_base + section_header->VirtualAddress, this->buffer + section_header->PointerToRawData, section_header->SizeOfRawData, nullptr))
		{
			std::cout << SUCCESS << "Mapped " << section_header->Name << " section" << std::endl;
			continue;
		}

		/* Failed to map section */
		std::cout << ERROR << "Failed to map " << section_header->Name << " section (" << GetLastError() << ")" << std::endl;
		return STATUS_UNSUCCESSFUL;
	}

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

	if (!this->process_handle)
	{
		std::cout << ERROR << "Invalid process handle" << std::endl;
		return STATUS_UNSUCCESSFUL;
	}

	if (!VirtualFreeEx(this->process_handle, this->module_base, NULL, MEM_RELEASE))
	{
		std::cout << ERROR << "VirtualFreeEx failed (" << GetLastError() << ")" << std::endl;
		return STATUS_UNSUCCESSFUL;
	}

	if (!CloseHandle(this->process_handle))
	{
		std::cout << ERROR << "CloseHandle failed (" << GetLastError() << ")" << std::endl;
		return STATUS_UNSUCCESSFUL;
	}

	std::cout << SUCCESS << "Successfully freed memory" << std::endl;
	this->process_handle = NULL;
	return STATUS_SUCCESS;
}
