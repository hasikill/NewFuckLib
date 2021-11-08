#pragma once
#include <Windows.h>
#include <stdint.h>

namespace fk
{
	class window
	{
	public:
		static BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam)
		{
			DWORD dwCurProcessId = *((DWORD*)lParam);
			DWORD dwProcessId = 0;

			GetWindowThreadProcessId(hwnd, &dwProcessId);
			if (dwProcessId == dwCurProcessId && GetParent(hwnd) == NULL)
			{
				*((HWND*)lParam) = hwnd;
				return FALSE;
			}
			return TRUE;
		}

		static HWND get_process_main_window(uint32_t process_id)
		{
			if (!EnumWindows(fk::window::EnumWindowsProc, (LPARAM)&process_id))
			{
				return (HWND)process_id;
			}
			return NULL;
		}

		static HWND get_self_main_window()
		{
			return get_process_main_window(GetCurrentProcessId());
		}
	};
}
