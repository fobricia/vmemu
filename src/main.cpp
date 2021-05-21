#include <iostream>
#include <unicorn/unicorn.h>
#include <cli-parser.hpp>
#include "vmemu_t.hpp"

int __cdecl main(int argc, const char* argv[])
{
	argparse::argument_parser_t parser("uc-tracer", 
		"VMProtect 2 Virtual Instruction Tracer Using Unicorn");

	parser.add_argument()
		.name("--vmentry").required(true)
		.description("relative virtual address to a vm entry...");

	parser.add_argument()
		.name("--vmpbin").required(true)
		.description("path to unpacked virtualized binary...");

	parser.add_argument()
		.name("--imagebase").required("true")
		.description("image base from optional PE header...");

	parser.enable_help();
	auto result = parser.parse(argc, argv);

	if (result)
	{
		std::printf("[!] error parsing commandline arguments... reason = %s\n", 
			result.what().c_str());

		return -1;
	}

	if (parser.exists("help"))
	{
		parser.print_help();
		return 0;
	}

	const auto vm_entry_rva = std::strtoull(
		parser.get<std::string>("vmentry").c_str(), nullptr, 16);

	const auto image_base = std::strtoull(
		parser.get<std::string>("imagebase").c_str(), nullptr, 16);

	const auto module_base = reinterpret_cast<std::uintptr_t>(
		LoadLibraryExA(parser.get<std::string>("vmpbin").c_str(), 
			NULL, DONT_RESOLVE_DLL_REFERENCES));

	vm::emu_t emu(vm_entry_rva, image_base, module_base);

	if (!emu.init()) 
	{
		std::printf("[!] failed to init emulator...\n");
		return -1; 
	}
}
