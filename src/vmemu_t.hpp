#pragma once
#include <exception>
#include <cstdint>
#include <unicorn/unicorn.h>
#include <xtils/xtils.hpp>
#include <vm.h>
#include <functional>
#include <mutex>

namespace vm
{
	class emu_t
	{
		using callback_t = std::function<void(uc_engine*, uint64_t, uint32_t, void*)>;
	public:
		explicit emu_t(std::uint32_t vm_entry_rva, 
			std::uintptr_t image_base, std::uintptr_t module_base);

		bool init();
		~emu_t();
	private:
		uc_engine* uc;
		uc_hook trace;

		std::uintptr_t image_base, module_base;
		std::uint32_t vm_entry_rva;

		zydis_routine_t vm_entry;
		std::uintptr_t* vm_handler_table;
		std::vector<vm::handler_t> vm_handlers;

		// very janky work around to use classes & callbacks with unicorn... it is what it is...
		callback_t jmp_hook = 
			[&, this](uc_engine* uc, uint64_t address, uint32_t size, void* user_data) -> void 
		{
			// grab JMP RDX/RCX <-- this register...
			static auto jmp_reg = vm_entry[
				vm_entry.size() - 1].instr.operands[0].reg.value;

			static ZydisDecoder decoder;
			static std::once_flag once;
			static ZydisDecodedInstruction instr;
			static std::uintptr_t reg_val = 0u;

			// init zydis decoder just a single time...
			std::call_once(once, []() -> void { 
				ZydisDecoderInit(&decoder, 
					ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64); });

			if (address == vm_entry[vm_entry.size() - 1].addr)
			{
				std::printf("stopped at jmp... addr = 0x%p\n", address);
				std::getchar();
			}
			// if we are getting a callback for a JMP RCX/RDX instruction...
			else if (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(
				&decoder, reinterpret_cast<void*>(address), size, &instr)) &&
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
					throw std::exception("invalid register to jump from...\n");
				}

				// checks to see if the address 
				// in JMP RDX/RCX is a vm handler address...
				static const auto vm_handler_check = 
					[&](vm::handler_t& vm_handler) -> bool 
				{ return vm_handler.address == reg_val; };

				if (std::find_if(vm_handlers.begin(), vm_handlers.end(),
					vm_handler_check) == vm_handlers.end())
					return;

				std::printf("stopped at jmp... addr = 0x%p\n", address);
				std::getchar();
			}
		};
	};
}