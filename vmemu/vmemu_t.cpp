#include "vmemu_t.hpp"

namespace vm
{
	emu_t::emu_t(std::uint32_t vm_entry_rva, 
		std::uintptr_t image_base, std::uintptr_t module_base)
		: 
		module_base(module_base), 
		image_base(image_base),
		vm_entry_rva(vm_entry_rva)
	{
		auto err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);

		if (err) 
			throw std::exception("failed to init unicorn", err);

		const auto image_size =
			NT_HEADER(module_base)->OptionalHeader.SizeOfImage;

		const auto vm_entry = vm_entry_rva + module_base;
		constexpr auto stack_addr = 0x1000000;

		// allocate space for module...
		uc_mem_map(uc, module_base, image_size, UC_PROT_ALL);

		// allocate 6 pages for stack...
		uc_mem_map(uc, stack_addr, 0x1000 * 6, UC_PROT_READ | UC_PROT_WRITE);

		// write the module into memory...
		uc_mem_write(uc, module_base, reinterpret_cast<void*>(module_base), image_size);

		// set vm_entry into RIP...
		uc_reg_write(uc, UC_X86_REG_RIP, &vm_entry);

		// set stack address up...
		uc_reg_write(uc, UC_X86_REG_RSP, &stack_addr);
	}

	emu_t::~emu_t()
	{
		uc_close(uc);
	}
}