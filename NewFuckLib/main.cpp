#include <iostream>
#include "fk_log.hpp"
#include "fk_file.hpp"
#include "fk_string.hpp"
#include "fk_crypto.hpp"

int main()
{
	// 字符串常用操作
	// 字符串截取
	fk::string str = "!!!115, 223, 12.56!!!";
	std::cout << str(3, -1) << std::endl;
	std::cout << str(-1, 3) << std::endl;
	std::cout << str(3, -1)(-1, 3) << std::endl;

	// 字符串分割 和 去空白
	fk::string str2 = str(3, -1)(-1, 3);
	std::vector<fk::string> str_list = str2.split(",");
	for (auto s : str_list)
	{
		std::cout << s.strtrim() << std::endl;
	}

	// 字符串到数字的转换
	printf("%d,%d,%f\n", str_list[0].number<int>(), str_list[1].number<int>(), str_list[2].number<float>());

	// 数字到字符串
	std::cout << fk::string::fromnumber<int>(10086) << std::endl;
	std::cout << fk::string::fromnumber<float>(3.1415f) << std::endl;

	// 字符串格式化
	std::cout << fk::string::fmtstr("%d-%02d-%d\n", 1997, 3, 12);

	// 字符串取前缀后缀
	std::cout << fk::string("111.222.zip").prefix("。|.") << std::endl;
	std::cout << fk::string("111.222.zip").suffix(".") << std::endl;

	// 日志库
	fk::log log = fk::log(
		FK_LOGTYPE_DEFAULT | fk::log::fkLogType::file,
		"a.log", "123456", false
	);
	log.put_successf("hello.");
	log.put_successf("hello1.");
	log.put_successf("hello2.");
	log.put_failedf("hello3.");
	//log.putf("hh = %d", 1);

	// 加密解密
	// base64
	fk::string a = fk::crypto_utils::base64_encode("123456", 6);
	std::cout << a << std::endl;
	std::cout << fk::crypto_utils::base64_decode(a.c_str(), a.size()) << std::endl;

	//base16
	fk::string b = fk::crypto_utils::base16_encode("123456", 6);
	std::cout << b << std::endl;
	std::cout << fk::crypto_utils::base16_decode(b.c_str(), b.size()) << std::endl;

	char plain_text[] = "There are moments in life when you miss someone so much that you just want to pick them from your dreams and hug them for real! Dream what you want to dream;go where you want to go;be what you want to";
	char user_key[] = "123456";
	// rc4

	// rc6
	fk::string ciphertext = fk::crypto_utils::rc6_encode(plain_text, sizeof(plain_text), user_key);
	std::cout << ciphertext.hexstring() << std::endl;
	std::cout << fk::crypto_utils::rc6_decode(ciphertext.c_str(), ciphertext.size(), user_key) << std::endl;

	return 0;
}
