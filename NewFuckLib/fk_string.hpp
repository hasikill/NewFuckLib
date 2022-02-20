#pragma once
#pragma warning(disable:4996)
#include <string>
#include <vector>
#include <sstream>
#include <regex>
#include <stdarg.h>
#include <Windows.h>
#include <codecvt>
#include <iostream>

namespace fk
{
	class string : public std::string
	{
	public:
		string() = default;
		string(const fk::string& s) : std::string(s) {}
		string(const std::string& s) : std::string(s) {}
		string(const char* s) : std::string(s) {}

		fk::string operator()(int n, int m = -1)
		{
			if (m == -1)
				return substr(n, size() - n);
			if (n == -1)
				return substr(0, size() - m);
			return substr(n, m);
		}

		std::vector<fk::string> split(const char* pattern)
		{
			string::size_type pos;
			std::vector<fk::string> result;
			std::string str = *this;

			str += pattern;
			size_t size = str.size();

			for (size_t i = 0; i < size; i++) {
				pos = str.find(pattern, i);
				if (pos < size) {
					std::string s = str.substr(i, pos - i);
					result.push_back(s);
					i = pos + strlen(pattern) - 1;
				}
			}
			return result;
		}

		std::vector<fk::string> split(fk::string& pattern)
		{
			return split(pattern.c_str());
		}

		std::vector<fk::string>& split(fk::string& pattern, std::vector<fk::string>& out)
		{
			string::size_type pos;
			std::string str = *this;

			str += pattern;
			size_t size = str.size();

			for (size_t i = 0; i < size; i++) {
				pos = str.find(pattern, i);
				if (pos < size) {
					std::string s = str.substr(i, pos - i);
					out.push_back(s);
					i = pos + pattern.size() - 1;
				}
			}
			return out;
		}

		fk::string subreplace(fk::string& sub_str, fk::string& new_str)
		{
			std::string resource_str = *this;
			string::size_type pos = 0;
			while ((pos = resource_str.find(sub_str)) != string::npos)
			{
				resource_str.replace(pos, sub_str.length(), new_str);
			}
			return resource_str;
		}

		fk::string getsubstr(const char* begin, const char* end)
		{
			auto begin_index = find(begin);
			if (begin_index != -1)
			{
				begin_index = begin_index + strlen(begin);
				auto end_index = find(end, begin_index);
				if (end_index != -1)
				{
					return (*this)(begin_index, (end_index - begin_index));
				}
			}
			return "";
		}

		fk::string prefix(const char* patterns)
		{
			fk::string res = "";
			fk::string& s = *this;
			std::vector<fk::string> ls = fk::string(patterns).split("|");
			for (auto pattern : ls)
			{
				int l = (int)s.find(pattern);
				if (l != -1)
				{
					res = s(-1, (int)size() - l);
					if (!res.empty())
						return res;
				}
			}
			return res;
		}

		fk::string suffix(const char* patterns)
		{
			fk::string res = "";
			fk::string& s = *this;
			std::vector<fk::string> ls = fk::string(patterns).split("|");
			for (auto pattern : ls)
			{
				int r = (int)s.rfind(pattern);
				if (r != -1)
				{
					res = s(r + 1, -1);
					if (!res.empty())
						return res;
				}
			}
			return res;
		}

		fk::string strtrimall()
		{
			std::regex re("\\s");
			return std::regex_replace(*this, re, "");
		}

		fk::string strtrim()
		{
			if (!empty())
			{
				const char* begin = c_str();
				const char* end = c_str() + size();

				for (; begin != end;)
				{
					if (*begin == ' ' || *begin == '\t' || *begin == '\r' || *begin == '\n')
					{
						begin++;
					}
					else
					{
						break;
					}
				}

				for (; begin != end;)
				{
					if (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r' || end[-1] == '\n')
					{
						end--;
					}
					else
					{
						break;
					}
				}

				auto ch_size = end - begin;
				if (end - begin > 0)
				{
					char* buf = new char[ch_size + 1] { 0 };
					memcpy(buf, begin, ch_size);
					fk::string str = buf;
					delete[] buf;
					return str;
				}
			}
			return "";
		}

		fk::string hexstring(const char* patterns = " ", bool isupper = false)
		{
			fk::string ret = "";
			for (auto ch : *this)
			{
				char tmp[16];
				sprintf_s(tmp, isupper ? "%02X" : "%02x", (uint8_t)ch);
				ret += tmp;
				ret += patterns;
			}
			return ret;
		}

		template <typename T>
		T number()
		{
			T result;
			std::istringstream is(*this);
			is >> result;
			return result;
		}

		std::wstring to_unicode()
		{
			int len = length();
			int unicode_len = ::MultiByteToWideChar(CP_ACP,
				0,
				c_str(),
				-1,
				NULL,
				0);
			wchar_t* unicode_buf = new wchar_t[unicode_len + 1] { 0 };
			::MultiByteToWideChar(CP_ACP,
				0,
				c_str(),
				-1,
				(LPWSTR)unicode_buf,
				unicode_len);
			std::wstring ret = unicode_buf;
			delete [] unicode_buf;
			return ret;
		}

		fk::string trad2simple()
		{
			std::string strSimple;
			if (size() == 0)
				return "";

			int nLen = size();
			char* pBuffer = new char[nLen + 1]{ 0 };
			if (pBuffer == nullptr)
				return "";

			LCMapStringA(2052, 33554432, c_str(), nLen, pBuffer, nLen);
			strSimple = pBuffer;

			if (pBuffer != nullptr)
				delete[] pBuffer;

			return strSimple;
		}

		std::wstring utf82unicode()
		{
			std::wstring ret;
			try {
				std::wstring_convert< std::codecvt_utf8<wchar_t> > wcv;
				ret = wcv.from_bytes(*this);
			}
			catch (const std::exception& e) {
				std::cerr << e.what() << std::endl;
			}
			return ret;
		}

		fk::string utf82ansi()
		{
			return unic2ansi((wchar_t*)utf82unicode().c_str());
		}

	public:
		template <typename T>
		static fk::string fromnumber(T number)
		{
			std::stringstream ss;
			ss << number;
			return ss.str();
		}

		static fk::string fmtstr(const char* fmt, ...)
		{
			va_list vl;
			va_start(vl, fmt);
			const int fmt_buf_size = 1024 * 10;
			char* buffer = new char[fmt_buf_size];
			vsprintf_s(buffer, fmt_buf_size, fmt, vl);
			fk::string strTmp = buffer;
			delete buffer;
			return strTmp;
		}

		static fk::string unic2ansi(wchar_t* wcsUnic)
		{
			std::string strAnsi;
			//拿转换后的长度
			int nNewLen = WideCharToMultiByte(
				936,
				512,
				wcsUnic,
				wcslen(wcsUnic),
				0, 0, 0, FALSE);
			if (nNewLen == 0)
				return "";

			char* pBuffer = new char[nNewLen + 1]{ 0 };
			if (pBuffer == nullptr)
				return "";

			WideCharToMultiByte(
				936,
				512,
				wcsUnic,
				-1,
				pBuffer, nNewLen, 0, FALSE);

			//结果
			strAnsi = pBuffer;
			if (pBuffer != nullptr)
				delete[] pBuffer;

			return strAnsi;
		}

		static fk::string unicode2utf8(const std::wstring& wstr)
		{
			std::string ret;
			try {
				std::wstring_convert<std::codecvt_utf8<wchar_t>> wcv;
				ret = wcv.to_bytes(wstr);
			}
			catch (const std::exception& e) {
				std::cerr << e.what() << std::endl;
			}
			return ret;
		}
	};
}
