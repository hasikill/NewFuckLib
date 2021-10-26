#pragma once
#include <iostream>
#include <stdint.h>
#include <Windows.h>
#include <chrono>
#include <mutex>
#include "fk_file.hpp"
#include "fk_crypto.hpp"
#include "fk_define.h"

#define FK_LOG_VERSION "1.0"
#define FK_LOGTYPE_DEFAULT		(fk::log::fkLogType::prefix | fk::log::fkLogType::console)
#define FK_LOGTYPE_PRE_FILE		(fk::log::fkLogType::prefix | fk::log::fkLogType::file)
#define FK_LOGTYPE_PRE_DBGVIEW	(fk::log::fkLogType::prefix | fk::log::fkLogType::dbgview)
#define FK_LOGTYPE_ALL			(fk::log::fkLogType::prefix | fk::log::fkLogType::file | fk::log::fkLogType::console |fk::log::fkLogType::dbgview | fk::log::fkLogType::encrypt)

namespace fk
{
	class log
	{
	public:
		union fkLogMask
		{
			uint32_t value;
			struct
			{
				uint32_t console : 1;
				uint32_t file : 1;
				uint32_t dbgview : 1;
				uint32_t prefix : 1;
				uint32_t encrypt : 1;
			} ctl;

			fkLogMask() : value(0) {}
			fkLogMask(uint32_t v) : value(v) {}
		};

		enum fkLogType
		{
			console = 1 << 0,	// 输出到控制台
			file = 1 << 1,		// 输出到文件
			dbgview = 1 << 2,	// 输出到DbgView
			prefix = 1 << 3,	// 输出日志前缀
			encrypt = 1 << 4	// 日志加密
		};

	public:
		log(fkLogMask msk = FK_LOGTYPE_DEFAULT,
			const char* filename = nullptr,
			const char* passwd = nullptr,
			bool isappend = false)
		{
			setmask(msk);
			setfile(filename, isappend);
			setpasswd(passwd);
		}

		log& setmask(fkLogMask msk)
		{
			m_log_ctl = msk;
			return *this;
		}

		log& setfile(const char* filename, bool isappend = false)
		{
			if (m_log_ctl.ctl.file == false)
				return *this;

			if (filename == nullptr || filename == "")
				return *this;

			m_log_file.open(filename, isappend ? "a+" : "w");
			return *this;
		}

		log& setpasswd(const char* passwd)
		{
			if (m_log_ctl.ctl.encrypt == false)
				return *this;

			if (passwd == nullptr)
				return *this;

			m_log_passwd = passwd;
			return *this;
		}

		log& write(const char* buf, size_t size)
		{
			m_log_mtx.lock();
			// 构建内容
			fk::string ctx = std::string(buf, size);

			// 内容加密
			if (m_log_ctl.ctl.encrypt)
			{
				if (m_log_passwd.empty())
				{
					const char* err = "'encrypt' mask is used but no password is specified.\n";
					OutputDebugStringA(err);
					throw err;
				}
				fk::string ciphertext = fk::crypto_utils::rc6_encode(ctx.c_str(), ctx.size(), m_log_passwd);
				ctx = "*" + fk::crypto_utils::base16_encode(ciphertext.c_str(), ciphertext.size()) + "*";
			}

			// 添加前缀
			if (m_log_ctl.ctl.prefix)
			{
				fk::string pref = getprefix();
				ctx = pref + ctx + "\n";
			}

			// 输出到文件
			if (m_log_ctl.ctl.file)
			{
				if (m_log_file.m_fp == nullptr)
				{
					const char* err = "'file' mask is used but no file path is specified.\n";
					OutputDebugStringA(err);
					throw err;
				}

				m_log_file.write(ctx).flush();
			}

			// 输出到控制台
			if (m_log_ctl.ctl.console)
			{
				std::cout << ctx;
			}

			// 输出到DbgView
			if (m_log_ctl.ctl.dbgview)
			{
				OutputDebugStringA(ctx.c_str());
			}

			m_log_mtx.unlock();
			return *this;
		}

		log& putf(const char* fmt, ...)
		{
			const int fmt_buf_size = 1024 * 10;
			char* buffer = new char[fmt_buf_size];
			va_list args;
			va_start(args, fmt);
			vsprintf_s(buffer, fmt_buf_size, fmt, args);
			va_end(args);
			write(buffer, strlen(buffer));
			delete buffer;
			return *this;
		}

		log& put(fk::string& str)
		{
			return putf(str.c_str());
		}

		log& put(fk::string&& str)
		{
			return putf(str.c_str());
		}

		void put_successf(const char* fmt, ...)
		{
			const int fmt_buf_size = 1024 * 10;
			char* buffer = new char[fmt_buf_size];
			va_list args;
			va_start(args, fmt);
			vsprintf_s(buffer, fmt_buf_size, fmt, args);
			va_end(args);
			put(fk::string::fmtstr("(+) %s", buffer));
			delete buffer;
			//return *this;
		}

		void put_errorf(const char* fmt, ...)
		{
			const int fmt_buf_size = 1024 * 10;
			char* buffer = new char[fmt_buf_size];
			va_list args;
			va_start(args, fmt);
			vsprintf_s(buffer, fmt_buf_size, fmt, args);
			va_end(args);
			put(fk::string::fmtstr("(-) %s", buffer));
			delete buffer;
			//return *this;
		}

		void close()
		{
			m_log_file.close();
		}

	protected:
		void settag(fk::string tag)
		{
			m_log_tag = tag;
		}

	private:
		fk::string getprefix()
		{
			auto now = std::chrono::system_clock::now();

			fk::string str_time;
			time_t t = std::chrono::system_clock::to_time_t(now);
			str_time = ctime(&t);
			str_time[str_time.size() - 1] = '\0';
			auto millsec = std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch());

			fk::string str_process_name;
			char full_path[MAX_PATH];
			GetModuleFileNameA(NULL, full_path, MAX_PATH);
			str_process_name = fk::string(full_path).suffix("/|\\");

			if (m_log_tag.empty())
			{
				return fk::string::fmtstr("[ver=%s,time=%s(%lld),pid=%d,tid=%d,name=%s]  ",
					FK_LOG_VERSION, str_time.c_str(), millsec.count(),
					GetCurrentProcessId(),
					GetCurrentThreadId(),
					str_process_name.c_str()
				);
			}
			else
			{
				return fk::string::fmtstr("[ver=%s,time=%s(%lld),pid=%d,tid=%d,name=%s,tag=%s]  ",
					FK_LOG_VERSION, str_time.c_str(), millsec.count(),
					GetCurrentProcessId(),
					GetCurrentThreadId(),
					str_process_name.c_str(),
					m_log_tag.c_str()
				);
			}
		}

	private:
		fk::file m_log_file;
		fk::string m_log_passwd;
		fkLogMask m_log_ctl;
		fk::string m_log_tag;
		std::mutex m_log_mtx;
	};

	class log_utils : protected log
	{
	public:
		log_utils(fk::string tag)
		{
			setmask(FK_LOG_UTILS_MASK);
			setfile(FK_LOG_UTILS_FILENAME, FK_LOG_UTILS_FILE_APPEND);
			setpasswd(FK_LOG_UTILS_PASSWD);
			settag(tag);
		}
	};
}
