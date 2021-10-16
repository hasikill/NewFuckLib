#pragma once
#include <stdio.h>
#include <string>

#pragma warning(disable:4996)

namespace fk
{
	class fk_file;
}

class fk_file
{
public:
	fk_file() = default;
	fk_file(const char* filename, const char* mode)
	{
		open(filename, mode);
	}

	~fk_file()
	{
	}

	fk_file& open(const char* filename, const char* mode)
	{
		m_filename = filename;
		m_fp = fopen(filename, mode);
		if (m_fp == nullptr)
			throw "open file error";
		return *this;
	}

	fk_file& write(std::string text)
	{
		if (m_fp == nullptr)
			throw "file not open";

		size_t resuide = text.length();
		while (resuide > 0)
		{
			size_t write_size = fwrite(text.c_str() + (text.length() - resuide), 1, resuide, m_fp);
			resuide -= write_size;
		}
		return *this;
	}

	fk_file& write(void* data, size_t data_size)
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

	fk_file& read(std::string& all_data)
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
	}

	fk_file& read(char* data, size_t size)
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

	size_t size()
	{
		struct _stat info;
		_stat(m_filename.c_str(), &info);
		size_t size = info.st_size;
		return size;
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
	static fk_file instance(const char* filename, const char* mode)
	{
		return fk_file(filename, mode);
	}

	static size_t get_file_size(const char* filename)
	{
		struct _stat info;
		_stat(filename, &info);
		size_t size = info.st_size;
		return size;
	}

private:
	FILE* m_fp = nullptr;
	std::string m_filename;
};
