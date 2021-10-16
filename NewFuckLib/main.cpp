#include <iostream>
#include "fk_file.hpp"

int main()
{
	fk_file::instance("hello", "w").write("Hello world!").close();
	return 0;
}
