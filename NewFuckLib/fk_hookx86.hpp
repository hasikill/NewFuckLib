#pragma once
#include "fk_ldasm.hpp"
#include <mutex>
#include <map>

namespace fk
{
#ifndef _WIN64
	// singleton
	class hook_x86
	{
	private:
		hook_x86() = default;

	public: // release memeory
		~hook_x86()
		{
			delete this;
		}



	public: // get instance
		static hook_x86* obj()
		{
			hook_x86* ret = nullptr;
			mtx_instance.lock();
			if (instance == nullptr)
				instance = new hook_x86();
			ret = instance;
			mtx_instance.unlock();
			return ret;
		}

	private:


		// singleton static instance
		static hook_x86* instance;
		static std::mutex mtx_instance;
	};
#endif
}
