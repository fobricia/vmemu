#include <iostream>
#include <fstream>
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
		.name("--imagebase").required(true)
		.description("image base from optional PE header...");

	parser.add_argument()
		.name("--out").required(true)
		.description("output file name for trace file...");

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

	std::vector<vmp2::entry_t> entries;
	vm::emu_t emu(vm_entry_rva, image_base, module_base);

	if (!emu.init()) 
	{
		std::printf("[!] failed to init emulator...\n");
		return -1; 
	}

	if (!emu.get_trace(entries))
		std::printf("[!] something failed during tracing, review the console for more information...\n");

	std::printf("> finished tracing...\n");
	std::printf("> creating trace file...\n");

	std::ofstream output(parser.get<std::string>("out"), 
		std::ios::binary);

	vmp2::file_header file_header;
	memcpy(&file_header.magic, "VMP2", sizeof("VMP2") - 1);

	file_header.epoch_time = time(nullptr);
	file_header.entry_offset = sizeof file_header;
	file_header.advancement = vmp2::exec_type_t::forward;
	file_header.version = vmp2::version_t::v1;
	file_header.module_base = module_base;
	file_header.entry_count = entries.size();

	output.write(reinterpret_cast<const char*>(
		&file_header), sizeof file_header);

	for (auto& entry : entries)
		output.write(reinterpret_cast<const char*>(
			&entry), sizeof entry);

	output.close();
	std::printf("> finished writing trace to disk...\n");
	std::getchar();
}
