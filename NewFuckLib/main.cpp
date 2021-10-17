#include <iostream>
#include "fk_log.hpp"
#include "fk_file.hpp"
#include "fk_string.hpp"

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
		FK_LOGTYPE_PRE_FILE |
		fk::log::fkLogType::console |
		fk::log::fkLogType::dbgview,
		"a.log", nullptr, false
	);
	log.put_successf("hello.");
	log.put_successf("hello1.");
	log.put_successf("hello2.");
	log.put_failedf("hello3.");
	//log.putf("hh = %d", 1);

	return 0;
}
