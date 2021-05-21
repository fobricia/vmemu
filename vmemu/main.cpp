#include <iostream>
#include <unicorn/unicorn.h>
#include <cli-parser.hpp>

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

	auto result = parser.parse(argc, argv);

	if (result)
	{
		std::printf("[!] error parsing commandline arguments... reason = %s\n", 
			result.what().c_str());

		return -1;
	}
}
