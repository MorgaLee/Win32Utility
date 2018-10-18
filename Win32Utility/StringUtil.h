#ifndef __STRINGUTIL_H__
#define __STRINGUTIL_H__

#include "Export.h"
#include <string>

class UTILITY_API CStringUtil
{
public:
    static std::string ws2s(std::wstring src);
    static std::wstring s2ws(std::string src);
};

#endif  // __STRINGUTIL_H__
