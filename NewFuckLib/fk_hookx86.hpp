#pragma once
#include "fk_ldasm.hpp"
#include "fk_pointer.hpp"
#include <mutex>
#include <map>
#include <vector>

namespace fk
{
#ifndef _WIN64

	struct st_hook_context
	{
		uintptr_t edi;
		uintptr_t esi;
		uintptr_t ebp;
		uintptr_t esp;
		uintptr_t ebx;
		uintptr_t edx;
		uintptr_t ecx;
		uintptr_t eax;
		uintptr_t eflag;
		uintptr_t eip;
	};

	// singleton
	class hook_x86 : protected fk::log_utils
	{
	private:
		enum em_hook
		{
			inline_hook,
			inline_raw,
			inline_general,
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

				struct
				{
					uintptr_t func_src;
					uintptr_t func_handler;
					uintptr_t func_raw;
					size_t affected_instrs_size;
				} inline_raw;

				struct
				{
					uintptr_t func_src;
					uintptr_t func_handler;
					char affected_instrs[32];
					size_t affected_instrs_size;
				} inline_general;

				struct
				{
					uintptr_t src_obj;
					uintptr_t src_index;
					uintptr_t func_src;
					uintptr_t func_handler;
					size_t max_params;
				} vtable;
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
			bool isdebug = false,
			size_t max_params = 10)
		{
			return add_inline_head(_func_src, _func_handler, isdebug, max_params, true);
		}

		template <typename S, typename D>
		hook_x86* add_inline_head(
			S _func_src,
			D _func_handler, 
			bool isdebug = false,
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
					(uint8_t)(isdebug ? 0xCC : 0x90),
					0x60,
					0x9C,
					0x8D, 0x74, 0x24, 0x24,
					0x83, 0xEC, (uint8_t)(max_params * sizeof(intptr_t)),
					0x89, 0xE7,
					0xB9, (uint8_t)max_params - 1, 0x00, 0x00, 0x00,
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

				p_shellcode = fix_shellcode(
					shellcode,
					sizeof(shellcode),
					info);
			}
			else
			{
				// member function deliver 'this' pointer use ecx register
				uint8_t shellcode[] = {
					(uint8_t)(isdebug ? 0xCC : 0x90),
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
					0x8D, 0x74, 0X24, 0X04,
					0x8D, 0x7C, 0x24, (uint8_t)((max_params * sizeof(intptr_t)) + 0x28),
					0xB9, (uint8_t)(max_params - 1), 0x00, 0x00, 0x00,
					0xF3, 0xA5,
					0x83, 0xC4, (uint8_t)(max_params * sizeof(intptr_t)),
					0x9D,
					0x61
				};

				p_shellcode = fix_shellcode(
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

		template <typename S, typename D>
		hook_x86* add_inline_raw(
			S _func_src,
			D _func_handler,
			bool isdebug = false)
		{
			uintptr_t func_src = (uintptr_t)_func_src;
			uintptr_t func_handler = (uintptr_t)_func_handler;

			// check func_src
			if (IsBadReadPtr((void*)func_src,
				10))
			{
				put_errorf("invalid address, func_src = %p\n", func_src);
				throw "invalid address";
			}

			st_hook info;
			info.type = inline_raw;
			info.inline_raw.func_src = func_src;
			info.inline_raw.func_handler = func_handler;

			// calculate the length of the affected instruction by the JMP instruction
			size_t affected_size =
				calc_affected(func_src, sizeof(st_trampoline));
			info.inline_raw.affected_instrs_size = affected_size;

			// Check remaining space
			if (m_use_offset +
				1 +
				affected_size +
				sizeof(st_trampoline) +
				10 >
				0x1000)
			{
				// allocate a new page
				new_page();
			}

			m_mtx_middle.lock();

			// copy to middle space
			pointer32 p =
				pointer32(m_use_space) +
				m_use_offset;

			// is debug
			p.write((uint8_t)(isdebug ? 0xCC : 0x90));
			m_use_offset += 1;

			// copy affected instrs to middle
			pointer32 p_affected = p.offset(1);
			p_affected.copy_from(
				func_src,
				affected_size);
			m_use_offset = m_use_offset +
				affected_size;
			info.inline_raw.func_raw = p.v();

			// fix jmp offset for affected
			size_t instr_offset = 0;
			while (instr_offset < affected_size)
			{
				pointer32 p_it = p_affected + instr_offset;
				size_t instr_size = calc_instr_size(p_it);
				bool is_jmp = is_jmp_instr(p_it);
				if (is_jmp) // if is jmp and fix
				{
					if (instr_size > 2)
					{	// 5 bytes jmp, fix jmp destination
						uintptr_t dest = calc_jmp5_dest(
							info.inline_raw.func_src +
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
				affected_size);
			st_trampoline trampoline_raw = calc_trampoline(
				p_jmp.v(),
				func_src +
				affected_size);
			p_jmp.copy_from(&trampoline_raw, sizeof(trampoline_raw));
			m_use_offset = m_use_offset +
				sizeof(trampoline_raw);

			m_mtx_middle.unlock();

			// add to maps
			m_mtx_hooks.lock();
			m_hooks.insert(std::pair<uintptr_t, st_hook>(func_src, info));
			m_mtx_hooks.unlock();

			// modify the source and jmp to destination
			st_trampoline trampoline = calc_trampoline(func_src, func_handler);
			fk::auto_mem_protect auto_protect(func_src, sizeof(trampoline));
			fk::pointer32(func_src).copy_from(&trampoline, sizeof(trampoline));
			return this;
		}

		template <typename S>
		S get_raw_func(S src_handler)
		{
			for (auto item : m_hooks)
			{
				auto& info = item.second;
				if (info.type == inline_raw)
				{
					if (info.inline_raw.func_handler == 
						(uintptr_t)src_handler)
					{
						return (S)info.inline_raw.func_raw;
					}
				}
			}
			return (S)0;
		}


		template <typename O, typename H>
		hook_x86* add_vtable_hook(
			O obj, 
			uint32_t index, 
			H handler,
			uint32_t param_count = 0,
			uint32_t max_params = 10)
		{
			pointer32 p_obj = obj;

			// check func_src
			if (IsBadReadPtr((void*)p_obj.v(),
				4))
			{
				put_errorf("invalid obj, obj = %p\n", p_obj.v());
				throw "invalid obj";
			}

			st_hook info;
			info.type = vtable_hook;

			// get vtable
			auto vtable = p_obj.ptr();

			// check func_src
			if (IsBadReadPtr((void*)vtable.v(),
				4))
			{
				put_errorf("invalid vtable, vtable = %p\n", vtable.v());
				throw "invalid vtable";
			}

			// get item
			auto item = vtable[index];

			// record
			info.vtable.src_obj = p_obj.v();
			info.vtable.src_index = index;
			info.vtable.func_src = item.v();
			info.vtable.func_handler = reinterpret_cast<uintptr_t>(handler);
			info.vtable.max_params = max_params;
			
			// member function deliver 'this' pointer use ecx register
			uint8_t shellcode[] = {
				0x55, 
				0x89, 0xE5, 
				0x51, 
				0x57,
				0x56,
				0x8D, 0x75, 0x08, 
				0x83, 0xEC, (uint8_t)(max_params * sizeof(intptr_t)),
				0x89, 0xE7, 
				0x51, 
				0xB9, (uint8_t)max_params, 0x00, 0x00, 0x00,
				0xF3, 0xA5, 
				0x59, 
				0x51, 
				0x68, 0x78, 0x56, 0x34, 0x12, 
				0xE8, 0x00, 0x00, 0x00, 0x00, 
				0x83, 0xC4, 0x08, 
				0x89, 0xE6, 
				0x8D, 0x7D, 0x08, 
				0xB9, (uint8_t)max_params, 0x00, 0x00, 0x00,
				0xF3, 0xA5, 
				0x83, 0xC4, (uint8_t)(max_params * sizeof(intptr_t)),
				0x5E, 
				0x5F,
				0x59,
				0x89, 0xEC, 
				0x5D, 
				0xC2, (uint8_t) param_count * sizeof(uintptr_t), 0x00
			};

			uintptr_t p_shellcode = fix_shellcode(
				shellcode,
				sizeof(shellcode),
				info);

			// add to maps
			m_mtx_hooks.lock();
			m_hooks.insert(std::pair<uintptr_t, st_hook>(vtable.offset(index * sizeof(uintptr_t)).v(), info));
			m_mtx_hooks.unlock();

			// modify the source item
			fk::pointer32 p_item = vtable.offset(index * sizeof(uintptr_t));
			fk::auto_mem_protect prot_item(p_item.v(), 4);

			p_item.write((uintptr_t)p_shellcode);
			return this;
		}
		
		template <typename S>
		hook_x86* add_inline_general(
			S _func_src,
			void (_cdecl* _func_handler)(st_hook_context* ),
			bool isdebug = false)
		{
			uintptr_t func_src = (uintptr_t)_func_src;
			uintptr_t func_handler = (uintptr_t)_func_handler;

			// check func_src
			if (IsBadReadPtr((void*)func_src,
				10))
			{
				put_errorf("invalid address, func_src = %p\n", func_src);
				throw "invalid address";
			}

			st_hook info;
			info.type = inline_general;
			info.inline_general.func_src = func_src;

			uint8_t shellcode[] =
			{
				(uint8_t)(isdebug ? 0xCC : 0x90),
				0x68, 0x78, 0x56, 0x34, 0x12, 
				0x9C, 
				0x60, 
				0x54, 
				0xE8, 0xC8, 0x3A, 0x41, 0x9B, 
				0x83, 0xC4, 0x04, 
				0x61, 
				0x9D, 
				0xC3
			};

			size_t shellcode_size = sizeof(shellcode);
			
			// calculate the length of the affected instruction by the JMP instruction
			size_t affected_size =
				calc_affected(func_src, sizeof(st_trampoline));
			pointer32(func_src).copy_to(
				info.inline_general.affected_instrs, affected_size);
			info.inline_general.affected_instrs_size =
				affected_size;
			
			// Check remaining space
			if (m_use_offset +
				affected_size +
				shellcode_size +
				10 >
				0x1000)
			{
				// allocate a new page
				new_page();
			}

			m_mtx_middle.lock();

			// copy to middle space
			pointer32 p =
				pointer32(m_use_space) +
				m_use_offset;

			// copy affected instrs to middle
			pointer32 p_affected = p.offset(0);
			p_affected.copy_from(
				info.inline_general.affected_instrs,
				info.inline_general.affected_instrs_size);
			m_use_offset = m_use_offset +
				info.inline_general.affected_instrs_size;

			// fix jmp offset
			size_t instr_offset = 0;
			while (instr_offset < info.inline_general.affected_instrs_size)
			{
				pointer32 p_it = p_affected + instr_offset;
				size_t instr_size = calc_instr_size(p_it);
				bool is_jmp = is_jmp_instr(p_it);
				if (is_jmp) // if is jmp and fix
				{
					if (instr_size > 2)
					{	// 5 bytes jmp, fix jmp destination
						uintptr_t dest = calc_jmp5_dest(
							info.inline_general.func_src +
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

			// copy shellcode
			pointer32 p_shellcode = p_affected.offset(
				info.inline_general.affected_instrs_size);
			p_shellcode.copy_from(shellcode, shellcode_size);

			// fix shellcode
			p_shellcode.offset(2) =
				func_src + info.inline_general.affected_instrs_size;
			p_shellcode.offset(10) =
				calc_jmp5_op(p_shellcode.offset(9).v(), func_handler);

			m_mtx_middle.unlock();

			m_use_offset = m_use_offset + shellcode_size + 10;

			// add to maps
			m_mtx_hooks.lock();
			m_hooks.insert(std::pair<uintptr_t, st_hook>(func_src, info));
			m_mtx_hooks.unlock();

			// modify the source and jmp to destination
			st_trampoline trampoline = calc_trampoline(func_src, p.v());
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

		template <typename S>
		hook_x86* remove_hook(S obj, uint32_t index)
		{
			fk::pointer32 p_obj(obj);
			uintptr_t func_src = p_obj.ptr().
				offset(index * sizeof(uintptr_t)).v();
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
				info.type == inline_hook_obj ||
				info.type == inline_general)
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
			else if (info.type == inline_raw)
			{
				// restore source function
				fk::auto_mem_protect auto_p(
					info.inline_raw.func_src,
					info.inline_raw.affected_instrs_size);
				fk::pointer32(
					info.inline_head.func_src).copy_from(
						info.inline_raw.func_raw + 1,
						info.inline_raw.affected_instrs_size
					);
			}
			else if (info.type == vtable_hook)
			{
				fk::pointer32 p_obj = info.vtable.src_obj;
				fk::pointer32 p_item = p_obj.ptr().offset(info.vtable.src_index).v();
				fk::auto_mem_protect auto_p(
					p_item.v(),
					4);
				p_item.write(info.vtable.func_src);
			}
		}

		uintptr_t fix_shellcode(
			uint8_t* shellcode, 
			size_t size, 
			st_hook& info)
		{
			// Check remaining space
			if (m_use_offset + 
				size + 
				(info.type == vtable_hook ? 0 : 
					info.inline_head.affected_instrs_size + 
					sizeof(st_trampoline)) +
				10 > 
				0x1000)
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
				p.offset(23) =
					calc_jmp5_op(p.offset(22).v(),
						info.inline_head.func_handler);
			}
			else if (info.type == inline_hook_obj)
			{
				p.offset(25) =
					calc_jmp5_op(p.offset(24).v(),
						info.inline_head.func_handler);
			}
			else if (info.type == vtable_hook)
			{
				p.offset(25) = info.vtable.func_src;
				p.offset(30) =
					calc_jmp5_op(p.offset(29).v(),
						info.vtable.func_handler);
			}

			if (info.type != vtable_hook)
			{
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
			}

			m_use_offset = m_use_offset + 10;
			m_mtx_middle.unlock();

			return p.v();
		}

		void new_page()
		{
			m_mtx_middle.lock();
			m_use_space = new char[0x1000];
			if (m_use_space == nullptr)
			{
				m_mtx_middle.unlock();
				put_errorf("not enough memory.");
				throw "not enough memory.";
			}
			memset(m_use_space, 0xcc, 0x1000);
			m_use_offset = 0;
			VirtualProtect(m_use_space, 0x1000, PAGE_EXECUTE_READWRITE, (PDWORD)&m_old_protect);

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

	template <typename T, typename A, typename B>
	inline T call_member(A obj, B func)
	{
		__asm mov ecx, obj;
		return (T)func;
	}
#endif
}
