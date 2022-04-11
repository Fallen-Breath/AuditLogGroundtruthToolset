#include <locale.h>
#include <stdio.h>
#include <sys/time.h>
#include <iostream>

int main()
{
    timeval tv;
    gettimeofday(&tv, nullptr);
    std::cout << "tv_sec: " << tv.tv_sec << std::endl;
    std::cout << "tv_usec: " << tv.tv_usec << std::endl;
    return 0;
}
