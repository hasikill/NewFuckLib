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
				: fk::log_utils(__FUNCTION__)
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

		class native : protected fk::log_utils
		{
		public:
			native(fk::string dllname)
				: fk::log_utils(__FUNCTION__)
			{
				m_dllname = dllname;
				m_remote_dll = nullptr;
			}

			bool install(HWND hWnd)
			{
				DWORD Pid;
				HANDLE    hProcess, hThread;
				DWORD   BytesWritten;
				LPVOID    mem;

				GetWindowThreadProcessId(hWnd, &Pid);

				put_successf("GetWindowThreadProcessId Pid = %d", Pid);
				m_pid = Pid;

				hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Pid);
				if (!hProcess)
				{
					put_errorf("OpenProcess error: %d", GetLastError());
					return false;
				}
				put_successf("OpenProcess hProcess = %p", hProcess);

				mem = VirtualAllocEx(hProcess, NULL, m_dllname.size(), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
				if (mem == NULL)
				{
					put_errorf("VirtualAllocEx error: %d", GetLastError());
					CloseHandle(hProcess);
					return 0;
				}
				put_successf("VirtualAllocEx mem = %p", mem);

				if (WriteProcessMemory(hProcess, mem, (LPVOID)m_dllname.c_str(), m_dllname.size(), &BytesWritten))
				{
					put_successf("WriteProcessMemory path = '%s'", m_dllname.c_str());

					auto entry = GetProcAddress(GetModuleHandleA("KERNEL32.DLL"), "LoadLibraryA");
					hThread = CreateRemoteThread(
						hProcess, 
						NULL, 0, 
						(LPTHREAD_START_ROUTINE)entry,
						mem, 0,
						NULL);
					if (!hThread)
					{
						put_errorf("CreateRemoteThread error: %d", GetLastError());
						VirtualFreeEx(hProcess, NULL, m_dllname.size(), MEM_RESERVE | MEM_COMMIT);
						CloseHandle(hProcess);
						return 0;
					}
					put_successf("CreateRemoteThread remote entry = %p", entry);

					DWORD wait_res = WaitForSingleObject(hThread, 10000);
					if (wait_res == WAIT_TIMEOUT)
					{
						put_errorf("WaitForSingleObject WAIT_TIMEOUT.");
						VirtualFreeEx(hProcess, NULL, m_dllname.size(), MEM_RESERVE | MEM_COMMIT);
						CloseHandle(hThread);
						CloseHandle(hProcess);
						return 0;
					}

					DWORD exit_code;
					if (!GetExitCodeThread(hThread, &exit_code))
					{
						put_errorf("GetExitCodeThread error: %d", GetLastError());
						VirtualFreeEx(hProcess, NULL, m_dllname.size(), MEM_RESERVE | MEM_COMMIT);
						CloseHandle(hThread);
						CloseHandle(hProcess);
						return 0;
					}

					m_remote_dll = reinterpret_cast<HMODULE>(exit_code);
					if (m_remote_dll == NULL)
						put_errorf("remote LoadLibraryA failed. module = %p", m_remote_dll);
					else
						put_successf("remote LoadLibraryA suceessfully. module = %p", m_remote_dll);

					VirtualFreeEx(hProcess, NULL, m_dllname.size(), MEM_RESERVE | MEM_COMMIT);
					CloseHandle(hThread);
					CloseHandle(hProcess);
					return 1;
				}

				put_errorf("WriteProcessMemory error: %d", GetLastError());
				VirtualFreeEx(hProcess, NULL, m_dllname.size(), MEM_RESERVE | MEM_COMMIT);
				CloseHandle(hProcess);
				return 0;
			}

			bool uninstall()
			{
				HANDLE    hProcess, hThread;

				if (m_remote_dll == nullptr)
				{
					put_errorf("not inject dll. remote_dll = %p", m_remote_dll);
					return false;
				}

				hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_pid);
				if (!hProcess)
				{
					put_errorf("OpenProcess error: %d", GetLastError());
					return false;
				}
				put_successf("OpenProcess hProcess = %p", hProcess);

				auto entry = GetProcAddress(GetModuleHandleA("KERNEL32.DLL"), "FreeLibrary");
				hThread = CreateRemoteThread(
					hProcess, 
					NULL, 0, 
					(LPTHREAD_START_ROUTINE)entry,
					m_remote_dll, 
					0, 
					NULL);
				if (!hThread)
				{
					put_errorf("CreateRemoteThread error: %d", GetLastError());
					CloseHandle(hProcess);
					return 0;
				}
				put_successf("CreateRemoteThread remote entry = %p", entry);

				DWORD wait_res = WaitForSingleObject(hThread, 10000);
				if (wait_res == WAIT_TIMEOUT)
				{
					put_errorf("WaitForSingleObject WAIT_TIMEOUT.");
					CloseHandle(hThread);
					CloseHandle(hProcess);
					return 0;
				}

				DWORD exit_code;
				if (!GetExitCodeThread(hThread, &exit_code))
				{
					put_errorf("GetExitCodeThread error: %d", GetLastError());
					CloseHandle(hThread);
					CloseHandle(hProcess);
					return 0;
				}

				if (exit_code == false)
				{
					put_errorf("remote FreeLibrary failed. module = %p", m_remote_dll);
				}
				else
				{
					put_successf("remote FreeLibrary suceessfully. module = %p", m_remote_dll);
					m_remote_dll = nullptr;
				}

				CloseHandle(hThread);
				CloseHandle(hProcess);
				return 1;
			}

		private:
			fk::string m_dllname;
			DWORD m_pid;
			HMODULE m_remote_dll;
		};
	}
}
