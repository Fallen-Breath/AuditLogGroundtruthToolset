#include <cstdio>

#define COSTY(expr) do{for (int i = 0; i < 1000000; i++) (expr);}while(false)

void func1()
{
	int x = 0;
	COSTY(x--);
}

void func2()
{
	for (int i = 0; i < 100; i++) func1();
	COSTY(1);
}


void func3()
{
	for (int i = 0; i < 10; i++) func2();
	COSTY(1);
}

int main()
{
	func3();
	return 0;
}
