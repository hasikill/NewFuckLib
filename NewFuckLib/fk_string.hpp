#pragma once
#include <string>
#include <vector>
#include <sstream>
#include <regex>
#include <stdarg.h>

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

		fk::string strtrim()
		{
			std::regex re("\\s");
			return std::regex_replace(*this, re, "");
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
	};
}
