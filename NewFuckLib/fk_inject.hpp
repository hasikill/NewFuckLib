#pragma once
#include <Windows.h>
#include <stdint.h>
#include "fk_log.hpp"
#include "fk_string.hpp"

namespace fk
{
	namespace inject
	{
		class winhook : protected fk::log_utils
		{
		public:
			winhook(fk::string dllname, fk::string exportfunc)
				: fk::log_utils("winhook")
			{
				m_dllname = dllname;
				m_exportfunc = exportfunc;
			}

			bool install(HWND hwnd)
			{
				if (hwnd == NULL)
				{
					put_errorf("hwnd == NULL");
					return false;
				}

				m_hwnd = hwnd;

				DWORD dwThreadId = GetWindowThreadProcessId(hwnd, NULL);
				if (dwThreadId == 0)
				{
					put_errorf("GetWindowThreadProcessId error: %d", GetLastError());
					return false;
				}
				put_successf("GetWindowThreadProcessId success. dwThreadId = %p", dwThreadId);

				HMODULE hDll = LoadLibraryA(m_dllname.c_str());
				if (hDll == NULL)
				{
					put_errorf("LoadLibraryA error: %d", GetLastError());
					put_errorf("LoadLibraryA path: %s", m_dllname.c_str());
					return false;
				}
				put_successf("LoadLibraryA success. hDll = %p", hDll);

				HOOKPROC lpFunc = (HOOKPROC)GetProcAddress(hDll, m_exportfunc.c_str());
				if (lpFunc == NULL)
				{
					put_errorf("GetProcAddress  error: %d", GetLastError());
					FreeLibrary(hDll);
					return false;
				}
				put_successf("GetProcAddress success. lpFunc = %p", lpFunc);

				m_hook = SetWindowsHookExA(WH_GETMESSAGE, lpFunc, hDll, dwThreadId);
				if (m_hook == NULL)
				{
					put_errorf("SetWindowsHookExA error: %d", GetLastError());
					FreeLibrary(hDll);
					return false;
				}
				put_successf("winhook install successful. m_hook = %p", m_hook);

				FreeLibrary(hDll);
				return true;
			}

			bool uninstall()
			{
				if (m_hook != NULL)
				{
					if (!UnhookWindowsHookEx(m_hook))
					{
						put_errorf("UnhookWindowsHookEx error: %d", GetLastError());
						return false;
					}
					m_hook = NULL;
				}
				put_successf("winhook uninstall successful.");
				return true;
			}

			bool send(uint32_t p1, uint32_t p2, uint32_t p3)
			{
				if (m_hwnd == NULL)
					return false;
				if (!PostMessageA(m_hwnd, p1, p2, p3))
				{
					put_errorf("PostMessageA error: %d", GetLastError());
					return false;
				}
				putf("PostMessage: %p, %p, %p", p1, p2, p3);
				return true;
			}

		private:
			fk::string m_dllname;
			fk::string m_exportfunc;
			HHOOK m_hook = NULL;
			HWND m_hwnd = NULL;
		};
	}
}
