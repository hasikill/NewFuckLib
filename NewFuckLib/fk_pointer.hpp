#pragma once
#include <Windows.h>
#include <stdint.h>
#include "fk_string.hpp"

namespace fk
{
	template <typename L = uint32_t>
	class pointer
	{
	public:
		template <typename T>
		pointer(T p)
		{
			this->p = (uintptr_t)p;
		}

		uintptr_t v()
		{
			return this->p;
		}

		template <typename T>
		pointer& copy_to(T buffer, size_t size)
		{
			memcpy((void*)buffer, (void*)this->p, size);
		}

		template <typename T>
		pointer& copy_from(T buffer, size_t size)
		{
			memcpy((void*)this->p, (void*)buffer, size);
		}

		pointer operator[](const int index)
		{
			return pointer<L>(*pointer<>(p + index * sizeof(p)));
		}

		pointer offset(int off)
		{
			return pointer<L>(p + off);
		}

		template <typename NT>
		NT number()
		{
			return *(NT*)p;
		}

		uint8_t byte()
		{
			return *(uint8_t*)p;
		}

		uint16_t word()
		{
			return *(::uint16_t*)p;
		}

		uint32_t dword()
		{
			return *(::uint32_t*)p;
		}

		uint64_t qword()
		{
			return *(::uint64_t*)p;
		}

		pointer ptr()
		{
			return *(::uintptr_t*)p;
		}

		fk::string string()
		{
			return (char*)p;
		}

		fk::string hex_string(size_t size, 
			const char* pattern = " ")
		{
			return fk::string(
				std::string((char*)this->p, 
					size)).hexstring(pattern);
		}

		template <typename S>
		pointer& operator=(S v)
		{
			*(S*)p = v;
			return *this;
		}

		template <typename S>
		pointer& write(S v)
		{
			*(S*)p = v;
			return *this;
		}

		L operator*()
		{
			return number<L>();
		}

		pointer operator+(int right)
		{
			return pointer<L>(p + right);
		}

		pointer operator-(int right)
		{
			return pointer<L>(p - right);
		}

	private:
		uintptr_t p;
	};

	using pointer64 = pointer<uint64_t>;
	using pointer32 = pointer<uint32_t>;
	using pointer16 = pointer<uint16_t>;
	using pointer8 = pointer<uint8_t>;

	class auto_mem_protect
	{
	public:
		template <typename T>
		auto_mem_protect(T addr, size_t size, uint32_t new_protect = PAGE_EXECUTE_READWRITE)
		{
			this->m_addr = (uintptr_t)addr;
			this->m_size = size;
			VirtualProtect((LPVOID)this->m_addr, size, new_protect, &this->m_old_protect);
		}

		~auto_mem_protect()
		{
			VirtualProtect((LPVOID)this->m_addr, this->m_size, this->m_old_protect, &this->m_old_protect);
		}

	private:
		DWORD m_old_protect;
		uintptr_t m_addr;
		size_t m_size;
	};
}
