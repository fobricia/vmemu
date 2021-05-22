#pragma once
#include <exception>
#include <cstdint>
#include <unicorn/unicorn.h>
#include <xtils/xtils.hpp>
#include <vm.h>
#include <functional>
#include <mutex>
#include <vmp2.hpp>

namespace vm
{
	class emu_t
	{
		using callback_t = std::function<void(uc_engine*, uint64_t, uint32_t, void*)>;
	public:
		explicit emu_t(std::uint32_t vm_entry_rva, 
			std::uintptr_t image_base, std::uintptr_t module_base);
		~emu_t();

		bool init();
		bool get_trace(std::vector<vmp2::entry_t>& entries);
	private:
		uc_err create_entry(vmp2::entry_t* entry);
		static void hook_code(uc_engine* uc, uint64_t address, uint32_t size, vm::emu_t* obj);
		static bool hook_mem_invalid(uc_engine* uc, uc_mem_type type,
			uint64_t address, int size, int64_t value, vm::emu_t* obj);

		uc_engine* uc;
		uc_hook trace, trace1;

		std::uintptr_t image_base, module_base;
		std::uint32_t vm_entry_rva;

		zydis_routine_t vm_entry;
		std::uintptr_t* vm_handler_table;
		std::vector<vm::handler_t> vm_handlers;
		std::vector<vmp2::entry_t>* trace_entries;
	};
}