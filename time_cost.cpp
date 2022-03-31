#include <cstdio>
#include <execinfo.h>

#define COSTY(expr) do{for (int i = 0; i < 1000000; i++) (expr);}while(false)

void func1()
{
	int x = 0;
	COSTY(x--);
}

void func2()
{
	for (int i = 0; i < 5; i++) func1();
	COSTY(1);
}


void func3()
{
	puts("printing some texts");
	for (int i = 0; i < 10; i++) func2();
	COSTY(1);
}

class MyClass
{
public:
    void runCostly(int amount)
    {
        for (int i = 0; i < amount; i++) func3();
    }
};

int main()
{
	MyClass().runCostly(2);
	return 0;
}
