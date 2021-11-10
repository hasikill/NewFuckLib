#pragma once
#include <stdio.h>
#include <io.h>
#include "fk_string.hpp"

#pragma warning(disable:4996)

namespace fk
{
	class file
	{
	public:
		file() = default;
		file(const char* filename, const char* mode)
		{
			open(filename, mode);
		}

		~file()
		{
		}

		file& open(const char* filename, const char* mode)
		{
			m_filename = filename;
			m_mode = mode;
			m_fp = fopen(filename, mode);
			if (m_fp == nullptr)
				throw "open file error";
			return *this;
		}

		file& reopen()
		{
			close();
			open(m_filename.c_str(), m_mode.c_str());
			return *this;
		}

		file& write(const char* text)
		{
			if (m_fp == nullptr)
				throw "file not open";

			size_t text_size = strlen(text);
			size_t resuide = text_size;
			while (resuide > 0)
			{
				size_t write_size = fwrite(text + (text_size - resuide), 1, resuide, m_fp);
				resuide -= write_size;
			}
			return *this;
		}

		file& write(fk::string text)
		{
			return write(text.c_str());
		}

		file& write(void* data, size_t data_size)
		{
			if (m_fp == nullptr)
				throw "file not open";

			size_t resuide = data_size;
			while (resuide > 0)
			{
				size_t write_size = fwrite((char*)data + (data_size - resuide), 1, resuide, m_fp);
				if (write_size == 0)
					throw "write error.";
				resuide -= write_size;
			}
			return *this;
		}

		file& read(fk::string& all_data)
		{
			if (m_fp == nullptr)
				throw "file not open";

			size_t file_size = size();
			all_data.reserve(file_size);

			size_t resuide = file_size;
			while (resuide > 0)
			{
				size_t read_size = fread((char*)all_data.c_str() + (file_size - resuide), 1, resuide, m_fp);
				if (read_size == 0)
					throw "read error.";
				resuide -= read_size;
			}
			return *this;
		}

		file& read(char* data, size_t size)
		{
			if (m_fp == nullptr)
				throw "file not open";

			size_t resuide = size;
			while (resuide > 0)
			{
				size_t read_size = fread((char*)data + (size - resuide), 1, resuide, m_fp);
				if (read_size == 0)
					throw "read error.";
				resuide -= read_size;
			}

			return *this;
		}

		file& size(size_t& out_size)
		{
			out_size = size();
			return *this;
		}

		size_t size()
		{
			struct _stat info;
			_stat(m_filename.c_str(), &info);
			size_t size = info.st_size;
			return size;
		}

		bool exits()
		{
			return file::exits(m_filename.c_str());
		}

		file& flush()
		{
			fflush(m_fp);
			return *this;
		}

		void close()
		{
			if (m_fp != nullptr)
			{
				fclose(m_fp);
				m_fp = nullptr;
			}
		}

	public:
		static file instance(const char* filename, const char* mode)
		{
			return file(filename, mode);
		}

		static size_t get_file_size(const char* filename)
		{
			struct _stat info;
			_stat(filename, &info);
			size_t size = info.st_size;
			return size;
		}

		static bool exits(const char* filename)
		{
			if (_access(filename, 0) == 0)
				return true;
			return false;
		}

		static fk::string temp_dir()
		{
			char buf[MAX_PATH] = "\0";
			GetTempPathA(MAX_PATH, buf);
			return buf;
		}
	private:
		FILE* m_fp = nullptr;
		fk::string m_filename;
		fk::string m_mode;

		friend class log;
	};
}
