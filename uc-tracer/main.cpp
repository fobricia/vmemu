#include <iostream>
#include <unicorn/unicorn.h>

int __cdecl main(int argc, const char* argv[])
{
	uc_err err;
	uc_engine* uc;

	err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);

	if (err)
	{
		std::printf("[!] uc open failed with: %u\n", err);
		return -1;
	}
}
