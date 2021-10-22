#pragma once
#include "fk_string.hpp"

#define FK_CRYPTO_BASE16TABLE	("125089abhwvABOZU")
#define FK_CRYPTO_BASE64TABLE	("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")

#define BITS_PER_BYTES 8
#define MAX_VALUE (1 << (BITS_PER_BYTES))

#define RC6_W 32
#define RC6_R 20

#ifndef max
#define max(x, y) ((x) > (y) ? (x) : (y));
#endif

#ifndef M_E
#define M_E  2.71828182845904523536
#endif

namespace fk
{
	class crypto
	{
	public:
		crypto() = default;

		fk::crypto& setkey(fk::string key)
		{
			this->key = key;
			return *this;
		}
		virtual fk::string encode(const char* data, size_t size) = 0;
		virtual fk::string decode(const char* data, size_t size) = 0;

	private:
		fk::string key;
	};

	class pkcs7
	{
	public:
		static fk::string padding(fk::string txt, int block_size = 16)
		{
			fk::string res = txt;
			char ch = (char)(block_size - txt.size() % block_size);
			for (char i = 0; i < ch; i++)
			{
				res += ch;
			}
			return res;
		}

		static fk::string unpadding(fk::string txt)
		{
			fk::string res = txt;
			int j = 0;
			char ch = txt[txt.size() - 1];
			for (uint8_t i = 0; i < (uint8_t)ch; i++)
			{
				if (txt[txt.size() - i - 1] != ch)
				{
					break;
				}
				j++;
			}

			if (j == ch)
			{
				res = txt(-1, j);
			}
			return res;
		}
	};

	class base16 : public fk::crypto
	{
	public:
		base16(const char base16_table[])
		{
			strcpy_s(this->base16_table, base16_table);
		}

		fk::crypto& encode(const char* data, size_t size, char* out, size_t* out_size)
		{
			fk::string ret = encode(data, size);
			memcpy(out, ret.c_str(), ret.size());
			*out_size = ret.size();
			return *this;
		}
		fk::crypto& decode(const char* data, size_t size, char* out, size_t* out_size)
		{
			fk::string ret = decode(data, size);
			memcpy(out, ret.c_str(), ret.size());
			*out_size = ret.size();
			return *this;
		}

		fk::string encode(const char* data, size_t size)
		{
			std::string res;
			for (size_t i = 0; i < size; i++)
			{
				int low_index = 0, high_index = 0;
				low_index = data[i] & 0xF;
				high_index = ((unsigned char)data[i] >> 4) & 0xF;
				res += base16_table[high_index];
				res += base16_table[low_index];
			}
			return res;
		}
		fk::string decode(const char* data, size_t size)
		{
			std::string res = "";
			if (size % 2 != 0)
				return "";

			char ch = 0;
			char j = 0;
			for (size_t i = 0; i < size; i += 2)
			{
				ch = 0;

				for (j = 0; j < sizeof(base16_table); j++)
				{
					if (data[i] == base16_table[j])
						break;
				}
				if (j >= sizeof(base16_table))
					return "";

				ch = ch | (j << 4);

				for (j = 0; j < sizeof(base16_table); j++)
				{
					if (data[i + 1] == base16_table[j])
						break;
				}
				if (j > sizeof(base16_table))
					return "";

				ch = ch | j;

				res += ch;
			}
			return res;
		}

	private:
		char base16_table[17];
	};

	class base64 : public fk::crypto
	{
	public:
		base64(const char base[])
		{
			strcpy_s(this->base, base);
		}

		fk::string encode(const char* data, size_t data_len)
		{
			//int data_len = strlen(data);   
			int prepare = 0;
			int temp = 0;
			fk::string ret;
			size_t tmp = 0;
			char changed[4];
			int i = 0, j = 0;

			while (tmp < data_len)
			{
				temp = 0;
				prepare = 0;
				memset(changed, '\0', 4);
				while (temp < 3)
				{
					//printf("tmp = %d\n", tmp);   
					if (tmp >= data_len)
					{
						break;
					}
					prepare = ((prepare << 8) | (data[tmp] & 0xFF));
					tmp++;
					temp++;
				}
				prepare = (prepare << ((3 - temp) * 8));
				//printf("before for : temp = %d, prepare = %d\n", temp, prepare);   
				for (i = 0; i < 4; i++)
				{
					if (temp < i)
					{
						changed[i] = 0x40;
					}
					else
					{
						changed[i] = (prepare >> ((3 - i) * 6)) & 0x3F;
					}
					ret += base[changed[i]];
					//printf("%.2X", changed[i]);
				}
			}

			return ret;
		}
		fk::string decode(const char* data, size_t data_len)
		{
			size_t ret_len = (data_len / 4) * 3;
			int equal_count = 0;
			fk::string ret;
			size_t tmp = 0;
			int temp = 0;
			int prepare = 0;
			int i = 0;
			if (*(data + data_len - 1) == '=')
			{
				equal_count += 1;
			}
			if (*(data + data_len - 2) == '=')
			{
				equal_count += 1;
			}
			if (*(data + data_len - 3) == '=')
			{//seems impossible   
				equal_count += 1;
			}
			switch (equal_count)
			{
			case 0:
				ret_len += 4;//3 + 1 [1 for NULL]   
				break;
			case 1:
				ret_len += 4;//Ceil((6*3)/8)+1   
				break;
			case 2:
				ret_len += 3;//Ceil((6*2)/8)+1   
				break;
			case 3:
				ret_len += 2;//Ceil((6*1)/8)+1   
				break;
			}
			ret.reserve(ret_len);
			while (tmp < (data_len - equal_count))
			{
				temp = 0;
				prepare = 0;
				while (temp < 4)
				{
					if (tmp >= (data_len - equal_count))
					{
						break;
					}
					prepare = (prepare << 6) | (find_pos(data[tmp]));
					temp++;
					tmp++;
				}
				prepare = prepare << ((4 - temp) * 6);
				for (i = 0; i < 3; i++)
				{
					if (i == temp)
					{
						break;
					}
					ret += (char)((prepare >> ((2 - i) * 8)) & 0xFF);
				}
			}
			return ret;
		}
		fk::crypto& encode(const char* data, size_t size, char* out, size_t* out_size)
		{
			fk::string ret = encode(data, size);
			memcpy(out, ret.c_str(), ret.size());
			*out_size = ret.size();
			return *this;
		}
		fk::crypto& decode(const char* data, size_t size, char* out, size_t* out_size)
		{
			fk::string ret = decode(data, size);
			memcpy(out, ret.c_str(), ret.size());
			*out_size = ret.size();
			return *this;
		}

	private:
		char find_pos(char ch)
		{
			char* ptr = (char*)strrchr(base, ch);//the last position (the only) in base[]   
			return (char)(ptr - base);
		}

	private:
		char base[65];
	};

	class rc4 : public crypto
	{
	public:
		rc4() = default;

		fk::rc4& setkey(fk::string key = "")
		{
			if (key.empty())
			{
				keylen = 8;
				srand((unsigned int)time(nullptr));
				K.push_back(rand() % MAX_VALUE);
			}
			else
			{
				keylen = key.size();
				for (size_t i = 0; i < key.size(); ++i)
					K.push_back(key[i]);
			}
			return *this;
		}

		fk::string encode(const char* data, size_t size)
		{
			uint8_t* out = new uint8_t[size];
			uint8_t* ks = new uint8_t[size];
			cipher((uint8_t*)data, size, out, ks);
			fk::string ret = std::string((char*)out, size);
			this->ks = std::string((char*)ks, size);
			delete ks;
			delete out;
			return ret;
		}

		fk::string decode(const char* data, size_t size)
		{
			uint8_t* out = new uint8_t[size];
			uint8_t* ks = new uint8_t[size];
			memcpy(ks, this->ks.c_str(), size);
			setkey();
			decipher((uint8_t*)data, size, out, ks);
			fk::string ret = std::string((char*)out, size);
			this->ks = std::string((char*)ks, size);
			delete ks;
			delete out;
			return ret;
		}

		rc4& cipher(uint8_t* in, size_t len, uint8_t* out, uint8_t* ks)
		{
			int i, j, t;
			for (i = 0; i < 256; ++i) {
				S[i] = i;
				T[i] = K[i % keylen];
			}

			j = 0;
			for (i = 0; i < 256; ++i) {
				j = (j + S[i] + T[i]) % 256;
				std::swap(S[i], S[j]);
			}

			for (size_t k = 0; k < len; ++k) {
				i = (i + 1) % 256;
				j = (j + S[i]) % 256;
				std::swap(S[i], S[j]);
				t = (S[i] + S[j]) % 256;
				ks[k] = S[t];
				out[k] = ks[k] ^ in[k];
			}

			return *this;
		}

		rc4& decipher(uint8_t* in, size_t len, uint8_t* out, uint8_t* ks) {
			for (size_t k = 0; k < len; ++k) {
				out[k] = ks[k] ^ in[k];
			}
			return *this;
		}

	private:
		std::vector<uint8_t> K;
		size_t keylen;
		uint8_t S[256];
		uint8_t T[256];
		fk::string ks;
	};

	class rc6 : public crypto
	{
	public:
		rc6(unsigned int W = RC6_W, unsigned int R = RC6_R)
		{
			w = W;
			r = R;
			log_w = (unsigned int)log2(w);
			modulo = (int64_t)std::pow(2, w);
			S = new unsigned int[2 * r + 4];
		}

		~rc6()
		{
			delete[] S;
		}

		rc6& setkey(fk::string key)
		{
			b = (unsigned int)key.size();

			const unsigned int w_bytes = (unsigned int)std::ceil((float)w / 8);
			const unsigned int c = (unsigned int)std::ceil((float)b / w_bytes);

			unsigned int p, q;
			rc_constraints(w, p, q);

			L = new unsigned int[c];
			for (uint32_t i = 0; i < c; i++) {
				L[i] = ((uint32_t*)key.c_str())[i];
			}

			S[0] = p;
			for (uint32_t i = 1; i <= (2 * r + 3); i++) {
				S[i] = (S[i - 1] + q) % modulo;
			}

			unsigned int A = 0, B = 0, i = 0, j = 0;
			int v = 3 * max(c, (2 * r + 4));
			for (int s = 1; s <= v; s++) {
				A = S[i] = left_rot((S[i] + A + B) % modulo, 3, w);
				B = L[j] = left_rot((L[j] + A + B) % modulo, (A + B), w);
				i = (i + 1) % (2 * r + 4);
				j = (j + 1) % c;
			}

			//printf("key S:\n%s\n", fk::string(std::string((char*)S, v)).hexstring().c_str());

			delete L;
			return *this;
		}

		fk::string encode(const char* data, size_t size)
		{
			fk::string res;
			size_t rounds = size / 16;
			for (size_t i = 0; i < rounds; i++)
			{
				res += encrypt_round(data + i * 16, 16);
			}

			if (size % 16 != 0)
			{
				fk::string pad = pkcs7::padding(std::string(data + rounds * 16, size % 16));
				res += encrypt_round(pad.c_str(), 16);
			}
			return res;
		}

		fk::string decode(const char* data, size_t size)
		{
			fk::string res;
			size_t rounds = size / 16;
			for (size_t i = 0; i < rounds; i++)
			{
				res += decrypt_round(data + i * 16, 16);
			}
			res = pkcs7::unpadding(res);
			return res;
		}
	private:
		fk::string encrypt_round(const char* data, size_t size)
		{
			unsigned int A, B, C, D;
			A = ((unsigned int*)data)[0];
			B = ((unsigned int*)data)[1];
			C = ((unsigned int*)data)[2];
			D = ((unsigned int*)data)[3];

			int32_t t, u, temp;

			B += S[0];
			D += S[1];
			for (uint32_t i = 1; i <= r; ++i) {
				t = left_rot((B * (2 * B + 1)) % modulo, log_w, w);
				u = left_rot((D * (2 * D + 1)) % modulo, log_w, w);
				A = left_rot((A ^ t), u, w) + S[2 * i];
				C = left_rot((C ^ u), t, w) + S[2 * i + 1];
				temp = A;
				A = B;
				B = C;
				C = D;
				D = temp;
			}

			A += S[2 * r + 2];
			C += S[2 * r + 3];

			unsigned int res[4] = { A, B, C, D };
			return std::string((char*)res, sizeof(res));
		}

		fk::string decrypt_round(const char* data, size_t size)
		{
			unsigned int A, B, C, D;
			A = ((unsigned int*)data)[0];
			B = ((unsigned int*)data)[1];
			C = ((unsigned int*)data)[2];
			D = ((unsigned int*)data)[3];

			unsigned int t, u, temp;

			C -= S[2 * r + 3];
			A -= S[2 * r + 2];
			for (int i = r; i >= 1; --i) {
				temp = D;
				D = C;
				C = B;
				B = A;
				A = temp;
				u = left_rot((D * (2 * D + 1)) % modulo, log_w, w);
				t = left_rot((B * (2 * B + 1)) % modulo, log_w, w);
				C = right_rot((C - S[2 * i + 1]) % modulo, t, w) ^ u;
				A = right_rot((A - S[2 * i]) % modulo, u, w) ^ t;
			}
			D -= S[1];
			B -= S[0];

			unsigned int res[4] = { A, B, C, D };
			return std::string((char*)res, sizeof(res));
		}

		void rc_constraints(const unsigned int& w, unsigned int& p, unsigned int& q)
		{
			p = (unsigned int)std::ceil(((M_E - 2) * std::pow(2, w)));
			q = (unsigned int)((1.618033988749895 - 1) * std::pow(2, w));    // Golden Ratio
		}

		int left_rot(unsigned int a, unsigned int b, unsigned int w) {
			b <<= w - log_w;
			b >>= w - log_w;
			return (a << b) | (a >> (w - b));
		}

		int right_rot(unsigned int a, unsigned int b, unsigned int w) {
			b <<= w - log_w;
			b >>= w - log_w;
			return (a >> b) | (a << (w - b));
		}

	private:
		unsigned int w, r, b, log_w;
		int64_t modulo;
		unsigned int* S;
		unsigned int* L;
	};

	class crypto_utils
	{
	public:
		static fk::string base16_encode(const char* data, size_t size, const char base16_table[] = FK_CRYPTO_BASE16TABLE)
		{
			return fk::base16(base16_table).encode(data, size);
		}
		static fk::string base16_decode(const char* data, size_t size, const char base16_table[] = FK_CRYPTO_BASE16TABLE)
		{
			return fk::base16(base16_table).decode(data, size);
		}

		static fk::string base64_encode(const char* data, size_t data_len, const char base[] = FK_CRYPTO_BASE64TABLE)
		{
			return fk::base64(base).encode(data, data_len);
		}
		static fk::string base64_decode(const char* data, size_t data_len, const char base[] = FK_CRYPTO_BASE64TABLE)
		{
			return fk::base64(base).decode(data, data_len);
		}

		static fk::string rc6_encode(const char* data, size_t data_len, fk::string key)
		{
			return fk::rc6().setkey(key).encode(data, data_len);
		}
		static fk::string rc6_decode(const char* data, size_t data_len, fk::string key)
		{
			return fk::rc6().setkey(key).decode(data, data_len);
		}

	};

}
