#pragma once
#include "fk_ldasm.hpp"
#include "fk_pointer.hpp"
#include <mutex>
#include <map>
#include <vector>

namespace fk
{
#ifndef _WIN64
	// singleton
	class hook_x86 : protected fk::log_utils
	{
	private:
		enum em_hook
		{
			inline_hook,
			inline_hook_obj,
			vtable_hook,

		};

		struct st_hook
		{
			em_hook type;

			union
			{
				struct
				{
					uintptr_t func_src;
					uintptr_t func_handler;
					char affected_instrs[32];
					size_t affected_instrs_size;
					size_t max_params;
				} inline_head;
			};
		};

#include <pshpack1.h>
		struct st_trampoline
		{
			uint8_t jmp;
			uint32_t address;
		};
#include <poppack.h>

	private:
		hook_x86() : fk::log_utils(__FUNCTION__)
		{
			new_page();
		}

	public: // release memeory
		~hook_x86()
		{
			release();
			delete this;
		}

		void release()
		{
			if (m_is_release == false)
			{
				m_is_release = true;

				// close all hooks
				clear();

				// release pools
				m_mtx_middle.lock();
				for (auto p : m_middle_pools)
				{
					if (p != nullptr)
						delete[] p;
				}
				m_middle_pools.clear();
				m_mtx_middle.unlock();
			}
		}

		template <typename S, typename D>
		hook_x86* add_inline_head_obj(
			S _func_src,
			D _func_handler,
			size_t max_params = 10)
		{
			return add_inline_head(_func_src, _func_handler, max_params, true);
		}

		template <typename S, typename D>
		hook_x86* add_inline_head(
			S _func_src,
			D _func_handler, 
			size_t max_params = 10,
			bool is_member = false)
		{
			uintptr_t func_src = (uintptr_t)_func_src;
			uintptr_t func_handler = (uintptr_t)_func_handler;

			st_hook info;

			info.type = is_member ? inline_hook_obj : inline_hook;

			// check func_src
			if (IsBadReadPtr((void*)func_src, 
				10))
			{
				put_errorf("invalid address, func_src = %p\n", func_src);
				throw "invalid address";
			}

			// calculate the length of the affected instruction by the JMP instruction
			size_t affected_size = 
				calc_affected(func_src, sizeof(st_trampoline));
			pointer32(func_src).copy_to(
				info.inline_head.affected_instrs, affected_size);
			info.inline_head.affected_instrs_size = 
				affected_size;

			info.inline_head.func_src = func_src;
			info.inline_head.func_handler = func_handler;
			info.inline_head.max_params = max_params;

			uintptr_t p_shellcode = 0;

			// generate trampoline shellcode
			if (is_member == false)
			{
				uint8_t shellcode[] = {
					0x60,
					0x9C,
					0x8D, 0x74, 0x24, 0x24,
					0x83, 0xEC, (uint8_t)(max_params * sizeof(intptr_t)),
					0x89, 0xE7,
					0xB9, (uint8_t)max_params, 0x00, 0x00, 0x00,
					0xF3, 0xA5,
					0x83, 0xC4, 0x04,
					0xE8, 0x00, 0x00, 0x00, 0x00,
					0x89, 0xE6,
					0x8D, 0x7C, 0x24, (uint8_t)((max_params * sizeof(intptr_t)) + 0x24),
					0xB9, (uint8_t)max_params, 0x00, 0x00, 0x00,
					0xF3, 0xA5,
					0x83, 0xC4, (uint8_t)(max_params * sizeof(intptr_t) - 4),
					0x9D,
					0x61
				};

				p_shellcode = fix_inline_head_shellcode(
					shellcode,
					sizeof(shellcode),
					info);
			}
			else
			{
				// member function deliver 'this' pointer use ecx register
				uint8_t shellcode[] = {
					0x60,
					0x9C,
					0x8D, 0x74, 0x24, 0x24,
					0x83, 0xEC, (uint8_t)(max_params * sizeof(intptr_t)),
					0x89, 0xE7,
					0x51,
					0xB9, (uint8_t)max_params, 0x00, 0x00, 0x00,
					0xF3, 0xA5,
					0x59,
					0x89, 0x0C, 0x24,
					0xE8, 0x00, 0x00, 0x00, 0x00,
					0x89, 0xE6,
					0x8D, 0x7C, 0x24, (uint8_t)((max_params * sizeof(intptr_t)) + 0x28),
					0xB9, (uint8_t)max_params, 0x00, 0x00, 0x00,
					0xF3, 0xA5,
					0x83, 0xC4, (uint8_t)(max_params * sizeof(intptr_t)),
					0x9D,
					0x61
				};

				p_shellcode = fix_inline_head_shellcode(
					shellcode,
					sizeof(shellcode),
					info);
			}

			// add to maps
			m_mtx_hooks.lock();
			m_hooks.insert(std::pair<uintptr_t, st_hook>(func_src, info));
			m_mtx_hooks.unlock();

			// modify the source and jmp to destination
			st_trampoline trampoline = calc_trampoline(func_src, p_shellcode);
			fk::auto_mem_protect auto_protect(func_src, sizeof(trampoline));
			fk::pointer32(func_src).copy_from(&trampoline, sizeof(trampoline));
			return this;
		}

		template <typename S>
		hook_x86* remove_hook(S _func_src)
		{
			uintptr_t func_src = (uintptr_t)_func_src;
			if (m_hooks.count(func_src) < 0)
			{
				put_errorf("remove_hook invalid _func_src, func_src = %p\n", func_src);
				throw "remove_hook invalid _func_src";
			}

			// get item
			st_hook& info = m_hooks[func_src];

			// restore
			restore_hook(info);

			// remove item from maps
			m_mtx_hooks.lock();
			m_hooks.erase(func_src);
			m_mtx_hooks.unlock();
			return this;
		}

		void clear()
		{
			for (auto item : m_hooks)
			{
				restore_hook(item.second);
			}

			m_mtx_hooks.lock();
			m_hooks.clear();
			m_mtx_hooks.unlock();
		}

	private:
		void restore_hook(st_hook& info)
		{
			if (info.type == inline_hook || 
				info.type == inline_hook_obj)
			{
				// restore source function
				fk::auto_mem_protect auto_p(
					info.inline_head.func_src,
					info.inline_head.affected_instrs_size);
				fk::pointer32(
					info.inline_head.func_src).copy_from(
					info.inline_head.affected_instrs,
					info.inline_head.affected_instrs_size
				);
			}
		}

		uintptr_t fix_inline_head_shellcode(
			uint8_t* shellcode, 
			size_t size, 
			st_hook& info)
		{
			// Check remaining space
			if (m_use_offset + 
				size + 
				info.inline_head.affected_instrs_size +
				sizeof(st_trampoline) + 10 > 
				USN_PAGE_SIZE)
			{
				// allocate a new page
				new_page();
			}

			m_mtx_middle.lock();

			// copy to middle space
			pointer32 p = 
				pointer32(m_use_space) +
				m_use_offset;
			
			p.copy_from(shellcode, size);
			m_use_offset = m_use_offset + size;

			// fix call handler
			if (info.type == inline_hook)
			{
				p.offset(22) =
					calc_jmp5_op(p.offset(21).v(),
						info.inline_head.func_handler);
			}
			else if (info.type == inline_hook_obj)
			{
				p.offset(24) =
					calc_jmp5_op(p.offset(23).v(),
						info.inline_head.func_handler);
			}

			// copy affected instrs to middle
			pointer32 p_affected = p.offset(size);
			p_affected.copy_from(
				info.inline_head.affected_instrs, 
				info.inline_head.affected_instrs_size);
			m_use_offset = m_use_offset +
				info.inline_head.affected_instrs_size;

			// fix jmp offset
			size_t instr_offset = 0;
			while (instr_offset < info.inline_head.affected_instrs_size)
			{
				pointer32 p_it = p_affected + instr_offset;
				size_t instr_size = calc_instr_size(p_it);
				bool is_jmp = is_jmp_instr(p_it);
				if (is_jmp) // if is jmp and fix
				{
					if (instr_size > 2)
					{	// 5 bytes jmp, fix jmp destination
						uintptr_t dest = calc_jmp5_dest(
							info.inline_head.func_src +
							instr_offset,
							p_it.offset(1).dword());

						// fix op
						p_it.offset(1) = calc_jmp5_op(p_it.v(), dest);
					}
					else
					{
						m_mtx_middle.unlock();
						put_errorf("invalid jmp short. %s\n",
							p_it.hex_string(instr_size).c_str());
						throw "not supported at the moment.";
					}
				}

				instr_offset = instr_offset + instr_size;
			}

			// add jmp to raw func
			pointer32 p_jmp = p_affected.offset(
				info.inline_head.affected_instrs_size);
			st_trampoline trampoline = calc_trampoline(
				p_jmp.v(), 
				info.inline_head.func_src + 
				info.inline_head.affected_instrs_size);
			p_jmp.copy_from(&trampoline, sizeof(trampoline));
			m_use_offset = m_use_offset +
				sizeof(trampoline);

			m_use_offset = m_use_offset + 10;
			m_mtx_middle.unlock();

			return p.v();
		}

		void new_page()
		{
			m_mtx_middle.lock();
			m_use_space = new char[USN_PAGE_SIZE];
			if (m_use_space == nullptr)
			{
				put_errorf("not enough memory.");
				m_mtx_middle.unlock();
				throw "not enough memory.";
			}
			memset(m_use_space, 0xcc, USN_PAGE_SIZE);
			m_use_offset = 0;
			VirtualProtect(m_use_space, USN_PAGE_SIZE, PAGE_EXECUTE_READWRITE, (PDWORD)&m_old_protect);

			m_middle_pools.push_back(m_use_space);
			m_mtx_middle.unlock();
		}

		// dest - src - 5 = op
		// op + src + 5 = dest
		uint32_t calc_jmp5_dest(uint32_t src, uint32_t opc)
		{
			return opc + src + 5;
		}

		// dest - src - 5 = op
		// op + src + 5 = dest
		uint32_t calc_jmp5_op(uint32_t src, uint32_t dest)
		{
			return dest - src - 5;
		}

		size_t calc_instr_size(pointer32 p)
		{
			return fk::ldasm::instr_size((void*)p.v());
		}

		bool is_jmp_instr(pointer32 p)
		{
			return fk::ldasm::obj().is_jmp((void*)p.v());
		}

		size_t calc_affected(uintptr_t addr, size_t length)
		{
			size_t ret = 0;
			for (;;)
			{
				size_t instr_size = fk::ldasm::obj().instr_size((void*)addr);
				addr = addr + instr_size;
				ret = ret + instr_size;
				if (ret >= length)
				{
					return ret;
				}
			}
			return 0;
		}

		st_trampoline calc_trampoline(uintptr_t src, uintptr_t dst)
		{
			return {
				0xe9, // jmp
				calc_jmp5_op(src, dst)
			};
		}

	public: // get instance
		static hook_x86* obj()
		{
			static hook_x86* instance = new hook_x86();
			return instance;
		}

	private:
		std::map<uintptr_t, st_hook> m_hooks;
		std::mutex m_mtx_hooks;

		std::vector<void*> m_middle_pools;
		std::mutex m_mtx_middle;

		void* m_use_space;	// springboard
		size_t m_use_offset;

		uint32_t m_old_protect;

		bool m_is_release = false;
	};
#endif
}
