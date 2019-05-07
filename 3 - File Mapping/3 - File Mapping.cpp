#include "stdafx.h"
#include <Windows.h>
#include <DbgHelp.h>
#include <atlbase.h>
#include <vector>
#include <string>
#include <utility>
#include <map>

LPCTSTR map_object_handler;

char* fromRva(DWORD rva) {
	return ((char*)map_object_handler) + rva;
}

int main(int argc, char *argv[])
{
	// retrieve name of file and map it to the memory
	if (argc < 2) {
		printf("No input file specified");
		return 1;
	}
	auto *name = argv[1];
	printf("Going to open file %s\n", name);

	auto file_handler = CreateFileA(
	    name,
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	if (!file_handler) {
		printf("Could not open file");
		return 1;
	}

	auto file_map = CreateFileMappingA(
		file_handler,
		NULL,
		PAGE_READONLY | SEC_IMAGE_NO_EXECUTE,
		0,
		0,
		NULL
	);
	if (!file_map) {
		printf("Could not map file to memory");
		return 1;
	}

	map_object_handler = (LPCTSTR)MapViewOfFile(
		file_map,
		FILE_MAP_READ,
		0,
		0,
		0
	);
	if (!map_object_handler) {
		printf("Could not get view of the file");
		return 1;
	}

	/* IMPORTS/EXPORTS PART */

	// get necessary headers
	auto *dos_header = (PIMAGE_DOS_HEADER) map_object_handler;
	printf("DOS header beginning: %.2s\n", dos_header[0]);

	auto *pe_header = (PIMAGE_NT_HEADERS)
		(((char*) map_object_handler) + dos_header->e_lfanew);
	printf("PE header beginning: %s\n", pe_header);

	auto *file_header = (PIMAGE_FILE_HEADER)&pe_header->FileHeader;

	// print all sections in this file and memorize their addresses
	std::vector<char*> sections_addresses;
	auto *section = (PIMAGE_SECTION_HEADER) 
		(((char*) pe_header)
			+ sizeof(pe_header->Signature)
			+ sizeof(pe_header->FileHeader)
			+ file_header->SizeOfOptionalHeader);
	auto *current_section = section;
	for (auto i = 0; i < file_header->NumberOfSections; ++i) {
		printf("Section %lu: %.8s\n", i, current_section->Name);
		sections_addresses.push_back(fromRva(current_section->VirtualAddress));
		current_section++;
	}

	// If there are exports(for .dll), print them as well before imports
	// addresses in 0x...

	// we need to know machine arch, so a little messy, but working approach
	DWORD export_descriptor_rva;
	DWORD import_descriptor_rva;
	switch (file_header->Machine) {
	case 0x014c: // x32
		export_descriptor_rva =
			((PIMAGE_OPTIONAL_HEADER32)&pe_header->OptionalHeader)
				->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
				.VirtualAddress;
		import_descriptor_rva = 
			((PIMAGE_OPTIONAL_HEADER32)&pe_header->OptionalHeader)
				->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
				.VirtualAddress;
		break;
	case 0x8664: // x64
		export_descriptor_rva =
			((PIMAGE_OPTIONAL_HEADER64)&pe_header->OptionalHeader)
				->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
				.VirtualAddress;
		import_descriptor_rva =
			((PIMAGE_OPTIONAL_HEADER64)&pe_header->OptionalHeader)
				->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
				.VirtualAddress;
		break;
	case 0x0200: // Intel Itanium
	default:     // unknown
		printf("cannot work with such machine architecture\n");
		return 1;
	}

	// retrieve export directory table
	auto *export_descriptor =
		(PIMAGE_EXPORT_DIRECTORY)fromRva(export_descriptor_rva);
	if ((char*)export_descriptor != (char*)map_object_handler) {
		// address of exports is image base => no exports; here, this is false
		auto *current_export = export_descriptor;
		auto current_export_number = 0;
		do {
			printf("\nExport %d: %s\n",
				current_export_number,
				fromRva(current_export->Name));

			char *current_function_addr = 
				fromRva(current_export->AddressOfNames);
			for (auto i = 0; i < current_export->NumberOfFunctions; ++i) {
				std::string func_name{ current_function_addr };
				printf(" %s\n", func_name);
				current_function_addr += func_name.size();
			}
		} while (current_export->Name != 0);
	}
	else {
		printf("\nno exports in this file\n");
	}

	// retrieve import directory table
	auto *import_descriptor = 
		(PIMAGE_IMPORT_DESCRIPTOR)fromRva(import_descriptor_rva);
	if (import_descriptor == nullptr) {
		printf("No imports in .idata section");
		return 1;
	}

	// print all imports
	auto *current_import = import_descriptor;
	auto current_import_number = 0;
	do {
		// print import
		printf("\nImport %d: %s\n",
			current_import_number,
			fromRva(current_import->Name));

		// print import's functions
		auto *import_lookup_table_entry = (PIMAGE_THUNK_DATA)
			fromRva(current_import->OriginalFirstThunk);
		while (import_lookup_table_entry->u1.AddressOfData != 0) {
			auto *import_hint_name_table_entry = (PIMAGE_IMPORT_BY_NAME)
				fromRva(import_lookup_table_entry->u1.AddressOfData);
			printf(" %s\n", import_hint_name_table_entry->Name);
			++import_lookup_table_entry;
		}

		++current_import;
		++current_import_number;
	} while (current_import->Name != 0);

	/* EXCEPTIONS PART */

	printf("\n");

	// seek to .pdata and skip 0s
	const auto *pdata_beginning_address = sections_addresses[4];
	auto *pdata_functions_beginning = pdata_beginning_address;
	while (*pdata_functions_beginning == 0) {
		++pdata_functions_beginning;
	}

	// fill stuctures with function names and addresses
	struct Function {
		DWORD begin;
		DWORD end;
		DWORD unwind;
	};
	std::vector<Function> functions;
	auto *functions_iter = (PRUNTIME_FUNCTION)pdata_functions_beginning;
	while (functions_iter->BeginAddress != 0) {
		functions.push_back(Function{
			functions_iter->BeginAddress,
			functions_iter->EndAddress,
			functions_iter->UnwindInfoAddress
		});
		++functions_iter;
	}

	for (size_t i = 0; i < functions.size(); ++i) {
		printf("function %d:\n", i);
		auto *unwind = fromRva(functions[i].unwind);
		auto unwind_codes = unwind[2] % 2 == 0 ? unwind[2] : unwind[2] + 1;
		printf(" there are %d unwind codes in this function\n", unwind_codes);

		switch (unwind[0]) {
		case 1: {
			printf(" the function does not have a specific exception handler\n");
			break;
		}
		case 9: {
			printf(" the function has a C_Specific exception handler\n");

			auto *scope_table = (PSCOPE_TABLE)unwind + 4 + 2 * unwind_codes + 4;
			auto handler = scope_table->ScopeRecord->HandlerAddress;
			printf(" handler address: %lu\n", handler);

			for (size_t j = 0; j < functions.size(); ++j) {
				if (functions[j].begin < handler && handler < functions[j].end) {
					printf(" this handler is in known function %d\n", j);
					printf(" thus, it is finally\n");
					break;
				}
			}

			if (scope_table->ScopeRecord->BeginAddress ==
				scope_table->ScopeRecord->EndAddress) {
				printf(" this function has a try-catch block\n");
			}

			break;
		}
		case 17: case 25: {
			printf(" the function uses SEH\n");

			auto *cur_address = unwind + 4 + 2 * unwind_codes;
			char addr_buf[4];
			addr_buf[0] = cur_address[3];
			addr_buf[1] = cur_address[2];
			addr_buf[2] = cur_address[1];
			addr_buf[3] = cur_address[0];
			DWORD address = (DWORD)addr_buf;
			printf(" termination handler address: %lu\n", address);

			for (size_t j = 0; j < functions.size(); ++j) {
				if (functions[j].begin < address && address < functions[j].end) {
					printf(" this handler is in known function %d\n", j);
					printf(" thus, it is finally\n");
					break;
				}
			}

			// try take next 4 dd-s, maybe they are RVAs to something
			for (auto j = 0; j < 4; ++j) {
				cur_address += 4;
				addr_buf[0] = cur_address[3];
				addr_buf[1] = cur_address[2];
				addr_buf[2] = cur_address[1];
				addr_buf[3] = cur_address[0];
				address = (DWORD)addr_buf;

				// check, if it's in the current function
				if (functions[i].begin < address && address < functions[i].end) {
					printf(" the function has a try-catch block, beginning at %lu\n",
						address);
					continue;
				}

				for (size_t z = 0; z < functions.size(); ++z) {
					if (functions[z].begin < address && address < functions[z].end) {
						printf(" the function has a finally at a "
							"known function %d\n", z);
						break;
					}
				}
			}

			break;
		}
		case 33:
			printf(" the function is a part of unwind chaining intself\n");
			break;
		}
	}

    return 0;
}
