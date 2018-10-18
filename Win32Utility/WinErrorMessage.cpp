#include "stdafx.h"
#include "WinErrorMessage.h"
#include <tchar.h>

CWinErrMsg::CWinErrMsg(int errCode)
    :m_errorCode(errCode)
{

}

CWinErrMsg::~CWinErrMsg()
{

}

tstring CWinErrMsg::GetFormattedMsg(TCHAR* pszModule/* = NULL*/)
{
    DWORD	dwFmtRt = 0;
    DWORD	dwFlags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_SYSTEM;
    LPVOID	lpMsgBuf = NULL;
    HMODULE hLookupMod = NULL;
    tstring	sMsg = _T("");

    if (pszModule != NULL) {
        hLookupMod = ::LoadLibraryEx(pszModule, NULL, LOAD_LIBRARY_AS_DATAFILE);
        if (hLookupMod) {
            dwFlags |= FORMAT_MESSAGE_FROM_HMODULE;
        }
    }

    dwFmtRt = ::FormatMessage(
        dwFlags,
        (LPCVOID)hLookupMod,
        m_errorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&lpMsgBuf,
        0,
        NULL);


    if (dwFmtRt != 0)	sMsg = (TCHAR*)lpMsgBuf;
    if (lpMsgBuf)		::LocalFree(lpMsgBuf);
    if (hLookupMod)	::FreeLibrary(hLookupMod);

    return sMsg;
}
