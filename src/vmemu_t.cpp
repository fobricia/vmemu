#include "vmemu_t.hpp"

namespace vm
{
	emu_t::emu_t(std::uint32_t vm_entry_rva, 
		std::uintptr_t image_base, std::uintptr_t module_base)
		: 
		module_base(module_base), 
		image_base(image_base),
		vm_entry_rva(vm_entry_rva),
		vm_handler_table(nullptr),
		uc(nullptr)
	{}

	bool emu_t::init()
	{
		//
		// vmprofiler init stuff...
		//

		if (!vm::util::flatten(vm_entry, vm_entry_rva + module_base))
		{
			std::printf("[!] failed to get vm entry...\n");
			return false;
		}

		//vm::util::deobfuscate(vm_entry);
		vm::util::print(vm_entry);

		if (!(vm_handler_table = vm::handler::table::get(vm_entry)))
		{
			std::printf("[!] failed to get vm handler table...\n");
			return false;
		}

		std::printf("> vm handler table = 0x%p\n", vm_handler_table);
		if (!vm::handler::get_all(module_base, image_base, vm_entry, vm_handler_table, vm_handlers))
		{
			std::printf("[!] failed to get all vm handlers...\n");
			return false;
		}

		//
		// unicorn init stuff...
		//

		auto err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);

		if (err)
		{
			std::printf("failed on uc_mem_map() with error returned %u: %s\n",
				err, uc_strerror(err));

			return false;
		}

		const auto image_size =
			NT_HEADER(module_base)->OptionalHeader.SizeOfImage;

		const auto vm_entry = vm_entry_rva + module_base;
		constexpr auto stack_addr = 0x1000000 + (0x1000 * 6);

		// allocate space for module...
		err = uc_mem_map(uc, module_base, image_size, UC_PROT_ALL);

		if (err)
		{
			std::printf("failed on uc_mem_map() with error returned %u: %s\n",
				err, uc_strerror(err));

			return false;
		}

		// allocate 6 pages for stack...
		err = uc_mem_map(uc, stack_addr, 0x1000 * 6, UC_PROT_ALL);

		if (err)
		{
			std::printf("failed on uc_mem_map() with error returned %u: %s\n",
				err, uc_strerror(err));

			return false;
		}

		// write the module into memory...
		err = uc_mem_write(uc, module_base, reinterpret_cast<void*>(module_base), image_size);

		if (err) std::printf("failed on uc_mem_write() with error returned %u: %s\n",
			err, uc_strerror(err));

		// set vm_entry into RIP...
		err = uc_reg_write(uc, UC_X86_REG_RIP, &vm_entry);

		if (err)
		{
			std::printf("failed on uc_reg_write() with error returned %u: %s\n",
				err, uc_strerror(err));

			return false;
		}

		// set stack address up...
		err = uc_reg_write(uc, UC_X86_REG_RSP, &stack_addr);

		if (err)
		{
			std::printf("failed on uc_reg_write() with error returned %u: %s\n",
				err, uc_strerror(err));

			return false;
		}

		err = uc_hook_add(uc, &trace, UC_HOOK_CODE, &jmp_hook,
			nullptr, module_base, module_base + image_size);

		if (err)
		{
			std::printf("failed on uc_hook_add() with error returned %u: %s\n",
				err, uc_strerror(err));

			return false;
		}

		// emulate machine code in infinite time
		err = uc_emu_start(uc, vm_entry, NULL, NULL, NULL);
		if (err)
		{
			std::printf("Failed on uc_emu_start() with error returned %u: %s\n",
				err, uc_strerror(err));

			return false;
		}

		return true;
	}

	emu_t::~emu_t()
	{
		if (uc) uc_close(uc);
	}
}