#include <iostream>
#include "fk.h"

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
	fk::log log(
		FK_LOGTYPE_DEFAULT | fk::log::fkLogType::file,
		"a.log", "123456", false
	);
	log.put_successf("hello.");
	log.put_successf("hello1.");
	log.put_successf("hello2.");
	log.put_errorf("hello3.");
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

	// create an empty structure (null)
	fkjson::json j;

	// add a number that is stored as double (note the implicit conversion of j to an object)
	j["pi"] = 3.141;

	// add a Boolean that is stored as bool
	j["happy"] = true;

	// add a string that is stored as std::string
	j["name"] = "Niels";

	// add another null object by passing nullptr
	j["nothing"] = nullptr;

	// add an object inside the object
	j["answer"]["everything"] = 42;

	// add an array that is stored as std::vector (using an initializer list)
	j["list"] = { 1, 0, 2 };

	// add another object (using an initializer list of pairs)
	j["object"] = { {"currency", "USD"}, {"value", 42.99} };

	// instead, you could also write (which looks very similar to the JSON above)
	fkjson::json j2 = {
	  {"pi", 3.141},
	  {"happy", true},
	  {"name", "Niels"},
	  {"nothing", nullptr},
	  {"answer", {
		{"everything", 42}
	  }},
	  {"list", {1, 0, 2}},
	  {"object", {
		{"currency", "USD"},
		{"value", 42.99}
	  }}
	};

	auto j3 = fkjson::json::parse(R"({"happy": true, "pi": 3.141})");

	std::cout << j.dump() << std::endl;
	std::cout << j2.dump() << std::endl;
	std::cout << j3.dump() << std::endl;

	return 0;
}
