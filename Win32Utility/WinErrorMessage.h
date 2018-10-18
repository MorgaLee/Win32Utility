/** 
    Author: Morgan.Li
    Date: 2018.10.18
*/

#ifndef __WINERRORMESSAGE_H__
#define __WINERRORMESSAGE_H__

#include "Export.h"
#include "Type.h"

class UTILITY_API CWinErrMsg
{
public:
    explicit CWinErrMsg(int errCode);
    ~CWinErrMsg();

    void SetErrorCode(int errCode) { m_errorCode = errCode; }
    int GetErrorCode() { return m_errorCode; }

    tstring GetFormattedMsg(TCHAR* pszModule = NULL);

private:
    int m_errorCode;
};

#endif  // __WINERRORMESSAGE_H__