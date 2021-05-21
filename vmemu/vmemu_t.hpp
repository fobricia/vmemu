#pragma once
#include <exception>
#include <cstdint>
#include <unicorn/unicorn.h>
#include <xtils/xtils.hpp>

namespace vm
{
	class emu_t
	{
	public:
		explicit emu_t(std::uint32_t vm_entry_rva, 
			std::uintptr_t image_base, std::uintptr_t module_base);

		~emu_t();
	private:
		std::uintptr_t image_base, module_base;
		std::uint32_t vm_entry_rva;
		uc_engine* uc;
	};
}