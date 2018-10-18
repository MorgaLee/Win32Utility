#include "stdafx.h"
#include "StringUtil.h"


std::string CStringUtil::ws2s(std::wstring src)
{
    std::locale sys_locale("");

    const wchar_t* data_from = src.c_str();
    const wchar_t* data_from_end = src.c_str() + src.size();
    const wchar_t* data_from_next = 0;

    int wchar_size = 4;
    char* data_to = new char[(src.size() + 1) * wchar_size];
    char* data_to_end = data_to + (src.size() + 1) * wchar_size;
    char* data_to_next = 0;

    memset(data_to, 0, (src.size() + 1) * wchar_size);

    typedef std::codecvt<wchar_t, char, mbstate_t> convert_facet;
    mbstate_t out_state = { 0 };
    auto result = std::use_facet<convert_facet>(sys_locale).out(
        out_state, data_from, data_from_end, data_from_next,
        data_to, data_to_end, data_to_next);
    if (result == convert_facet::ok)
    {
        std::string dst = data_to;
        delete[] data_to;
        return dst;
    }
    else
    {
        printf("convert error!\n");
        delete[] data_to;
        return std::string("");
    }
}

std::wstring CStringUtil::s2ws(std::string src)
{
    std::locale sys_locale("");

    const char* data_from = src.c_str();
    const char* data_from_end = src.c_str() + src.size();
    const char* data_from_next = 0;

    wchar_t* data_to = new wchar_t[src.size() + 1];
    wchar_t* data_to_end = data_to + src.size() + 1;
    wchar_t* data_to_next = 0;

    wmemset(data_to, 0, src.size() + 1);

    typedef std::codecvt<wchar_t, char, mbstate_t> convert_facet;
    mbstate_t in_state = { 0 };
    auto result = std::use_facet<convert_facet>(sys_locale).in(
        in_state, data_from, data_from_end, data_from_next,
        data_to, data_to_end, data_to_next);
    if (result == convert_facet::ok)
    {
        std::wstring dst = data_to;
        delete[] data_to;
        return dst;
    }
    else
    {
        delete[] data_to;
        return std::wstring(L"");
    }
}
