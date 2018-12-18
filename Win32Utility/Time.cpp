#include "stdafx.h"
#include "Time.h"

__int64 CTime::GetMillisecondSecond()
{
    FILETIME ft_now;
    GetSystemTimeAsFileTime(&ft_now);
    __int64 ll_now = (LONGLONG)ft_now.dwLowDateTime + ((LONGLONG)(ft_now.dwHighDateTime) << 32LL);
    ll_now -= 116444736000000000LL;
    return ll_now / 10000;
}