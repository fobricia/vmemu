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
		uc(nullptr),
		trace_entries(nullptr)
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

		vm::util::deobfuscate(vm_entry);
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
		std::printf("> got all vm handlers...\n");

		//
		// unicorn init stuff...
		//

		const auto image_size =
			NT_HEADER(module_base)->OptionalHeader.SizeOfImage;

		std::uintptr_t stack_base = 0x1000000;
		std::uintptr_t stack_addr = stack_base + (0x1000 * 20);

		uc_err err;
		if ((err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc)))
		{
			std::printf("failed on uc_mem_map() with error returned %u: %s\n",
				err, uc_strerror(err));

			return false;
		}

		if ((err = uc_mem_map(uc, module_base, image_size, UC_PROT_ALL)))
		{
			std::printf("failed on uc_mem_map() with error returned %u: %s\n",
				err, uc_strerror(err));

			return false;
		}

		if ((err = uc_mem_map(uc, 0x1000000, 0x1000 * 20, UC_PROT_ALL)))
		{
			std::printf("failed on uc_mem_map() with error returned %u: %s\n",
				err, uc_strerror(err));

			return false;
		}

		if ((err = uc_mem_write(uc, module_base, reinterpret_cast<void*>(module_base), image_size)))
		{
			std::printf("failed on uc_mem_write() with error returned %u: %s\n",
				err, uc_strerror(err));

			return false;
		}

		if ((err = uc_reg_write(uc, UC_X86_REG_RIP, &vm_entry)))
		{
			std::printf("failed on uc_reg_write() with error returned %u: %s\n",
				err, uc_strerror(err));

			return false;
		}

		if ((err = uc_reg_write(uc, UC_X86_REG_RSP, &stack_addr)))
		{
			std::printf("failed on uc_reg_write() with error returned %u: %s\n",
				err, uc_strerror(err));

			return false;
		}

		if ((err = uc_hook_add(uc, &trace, UC_HOOK_CODE, &vm::emu_t::hook_code,
			this, module_base, module_base + image_size)))
		{
			std::printf("failed on uc_hook_add() with error returned %u: %s\n",
				err, uc_strerror(err));

			return false;
		}

		if ((err = uc_hook_add(uc, &trace1, UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED,
			vm::emu_t::hook_mem_invalid, this, 1, 0)))
		{
			std::printf("failed on uc_hook_add() with error returned %u: %s\n",
				err, uc_strerror(err));

			return false;
		}
		return true;
	}

	emu_t::~emu_t()
	{
		if (uc) uc_close(uc);
	}

	bool emu_t::get_trace(std::vector<vmp2::entry_t>& entries)
	{
		// hook_code will fill this vector up with values...
		trace_entries = &entries;
		uc_err err;

		if ((err = uc_emu_start(uc, vm_entry_rva + module_base, NULL, NULL, NULL)))
		{
			std::printf("failed on uc_emu_start() with error returned %u: %s\n",
				err, uc_strerror(err));

			return false;
		}
		return true;
	}

	uc_err emu_t::create_entry(vmp2::entry_t* entry)
	{
		uc_reg_read(uc, UC_X86_REG_R15, &entry->regs.r15);
		uc_reg_read(uc, UC_X86_REG_R14, &entry->regs.r14);
		uc_reg_read(uc, UC_X86_REG_R13, &entry->regs.r13);
		uc_reg_read(uc, UC_X86_REG_R12, &entry->regs.r12);
		uc_reg_read(uc, UC_X86_REG_R11, &entry->regs.r11);
		uc_reg_read(uc, UC_X86_REG_R10, &entry->regs.r10);
		uc_reg_read(uc, UC_X86_REG_R9, &entry->regs.r9);
		uc_reg_read(uc, UC_X86_REG_R8, &entry->regs.r8);
		uc_reg_read(uc, UC_X86_REG_RBP, &entry->regs.rbp);
		uc_reg_read(uc, UC_X86_REG_RDI, &entry->regs.rdi);
		uc_reg_read(uc, UC_X86_REG_RSI, &entry->regs.rsi);
		uc_reg_read(uc, UC_X86_REG_RDX, &entry->regs.rdx);
		uc_reg_read(uc, UC_X86_REG_RCX, &entry->regs.rcx);
		uc_reg_read(uc, UC_X86_REG_RBX, &entry->regs.rbx);
		uc_reg_read(uc, UC_X86_REG_RAX, &entry->regs.rax);
		uc_reg_read(uc, UC_X86_REG_EFLAGS, &entry->regs.rflags);

		entry->vip = entry->regs.rsi;
		entry->handler_idx = entry->regs.rax;
		entry->decrypt_key = entry->regs.rbx;

		uc_err err;
		if ((err = uc_mem_read(uc, entry->regs.rdi,
			entry->vregs.raw, sizeof entry->vregs.raw)))
			return err;

		// copy virtual stack values...
		for (auto idx = 0u; idx < sizeof(entry->vsp) / 8; ++idx)
			if ((err = uc_mem_read(uc, entry->regs.rbp + (idx * 8),
				&entry->vsp.qword[idx], sizeof entry->vsp.qword[idx])))
				return err;

		return UC_ERR_OK;
	}

	void emu_t::hook_code(uc_engine* uc, uint64_t address, uint32_t size, vm::emu_t* obj)
	{
		std::printf(">>> Tracing instruction at 0x%p, instruction size = 0x%x\n", address, size);

		// grab JMP RDX/RCX <-- this register...
		static const auto jmp_reg = obj->vm_entry[obj->vm_entry.size()]
			.instr.operands[0]
			.reg
			.value;

		static ZydisDecoder decoder;
		static std::once_flag once;
		static ZydisDecodedInstruction instr;
		static std::uintptr_t reg_val = 0u;

		// init zydis decoder just a single time...
		std::call_once(once, [&]() -> void {
			ZydisDecoderInit(&decoder,
				ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64); });

		if (address == obj->vm_entry[obj->vm_entry.size()].addr)
		{
			std::printf("stopped at jmp... addr = 0x%p\n", address);
			std::getchar();

			vmp2::entry_t new_entry;
			if (!obj->create_entry(&new_entry))
			{
				std::printf("[!] failed to create new entry... exiting...\n");
				exit(0);
			}
			obj->trace_entries->push_back(new_entry);
		}
		// if we are getting a callback for a JMP RCX/RDX instruction...
		else if (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(
			&decoder, reinterpret_cast<void*>(address), size, &instr)) &&
			instr.mnemonic == ZYDIS_MNEMONIC_JMP &&
			instr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
			instr.operands[0].reg.value == jmp_reg)
		{
			switch (jmp_reg)
			{
			ZYDIS_REGISTER_RDX:
				uc_reg_read(uc, UC_X86_REG_RDX, &reg_val);
				break;
			ZYDIS_REGISTER_RCX:
				uc_reg_read(uc, UC_X86_REG_RCX, &reg_val);
				break;
			default:
				std::printf("[!] invalid jump register...\n");
				exit(0);
			}

			// checks to see if the address 
			// in JMP RDX/RCX is a vm handler address...
			static const auto vm_handler_check =
				[&](const vm::handler_t& vm_handler) -> bool
			{ return vm_handler.address == reg_val; };

			if (std::find_if(obj->vm_handlers.begin(), obj->vm_handlers.end(),
				vm_handler_check) == obj->vm_handlers.end())
				return;

			std::printf("stopped at jmp... addr = 0x%p\n", address);
			std::getchar();

			vmp2::entry_t new_entry;
			if (!obj->create_entry(&new_entry))
			{
				std::printf("[!] failed to create new entry... exiting...\n");
				exit(0);
			}
			obj->trace_entries->push_back(new_entry);
		}
	}

	bool emu_t::hook_mem_invalid(uc_engine* uc, uc_mem_type type,
		uint64_t address, int size, int64_t value, vm::emu_t* obj)
	{
		switch (type)
		{
		default:
			// return false to indicate we want to stop emulation
			return false;
		case UC_MEM_WRITE_UNMAPPED:
			printf(">>> Missing memory is being WRITE at 0x%p, data size = %u, data value = 0x%p\n",
				address, size, value);
			return false;
		case UC_MEM_READ_UNMAPPED:
			printf(">>> Missing memory is being READ at 0x%p, data size = %u, data value = 0x%p\n",
				address, size, value);
			return false;
		}
	}
}