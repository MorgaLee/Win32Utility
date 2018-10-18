#include "stdafx.h"
#include "NetworkAdapter.h"
#include "StringUtil.h"
#include <iphlpapi.h>
#include <tchar.h>

#pragma comment(lib, "iphlpapi.lib")

CNetworkAdapter::CNetworkAdapter(int adapterIndex)
    :m_dwIndex(-1)
    , m_nAdapterType(0)
    , m_bDhcpUsed(false)
    , m_bWinsUsed(false)
{

}

CNetworkAdapter::~CNetworkAdapter()
{

}

int CNetworkAdapter::FindPrimaryAdapter()
{
    IP_ADAPTER_INFO* pAdapterInfo = NULL;
    ULONG ulen = 0;
    ULONG errNum = 0;
    errNum = ::GetAdaptersInfo(pAdapterInfo, &ulen);
    if (errNum == ERROR_BUFFER_OVERFLOW)
    {
        pAdapterInfo = (IP_ADAPTER_INFO*)malloc(ulen);
        errNum = ::GetAdaptersInfo(pAdapterInfo, &ulen);
    }

    IP_ADAPTER_INFO* pNextAdapter = pAdapterInfo;
    int minIndex = pNextAdapter->Index;
    while (pNextAdapter != NULL)
    {
        if (pNextAdapter->Index < minIndex)
        {
            minIndex = pNextAdapter->Index;
        }

        pNextAdapter = pNextAdapter->Next;
    }

    free(pAdapterInfo);
    return minIndex;
}

bool CNetworkAdapter::ObtainAllAdapterIndex(std::vector<int>& indexArr)
{
    IP_ADAPTER_INFO* pAdapterInfo = NULL;
    ULONG ulen = 0;
    ULONG errNum = 0;
    errNum = ::GetAdaptersInfo(pAdapterInfo, &ulen);
    if (errNum == ERROR_BUFFER_OVERFLOW)
    {
        pAdapterInfo = (IP_ADAPTER_INFO*)malloc(ulen);
        errNum = ::GetAdaptersInfo(pAdapterInfo, &ulen);
    }

    IP_ADAPTER_INFO* pNextAdapter = pAdapterInfo;
    int minIndex = pNextAdapter->Index;
    while (pNextAdapter != NULL)
    {
        indexArr.push_back(pNextAdapter->Index);
        pNextAdapter = pNextAdapter->Next;
    }

    free(pAdapterInfo);
    return true;
}

bool CNetworkAdapter::SetupAdapter(CNetworkAdapter* pAdapter)
{
    if (pAdapter == NULL)
    {
        return false;
    }

    int adapterIndex = pAdapter->GetIndex();
    if(adapterIndex <= 0)
    {
        return false;
    }

    IP_ADAPTER_INFO* pAdapterInfo = NULL;
    ULONG ulen = 0;
    ULONG errNum = 0;
    errNum = ::GetAdaptersInfo(pAdapterInfo, &ulen);
    if(errNum == ERROR_BUFFER_OVERFLOW)
    {
        pAdapterInfo = (IP_ADAPTER_INFO*)malloc(ulen);
        errNum = ::GetAdaptersInfo(pAdapterInfo, &ulen);
    }

    IP_ADAPTER_INFO* pAI = NULL;
    IP_ADAPTER_INFO* pNext = pAdapterInfo;
    while(pNext != NULL)
    {
        if(pNext->Index == adapterIndex)
        {
            pAI = pNext;
        }

        pNext = pNext->Next;
    }

    if(pAI == NULL)
    {
        free(pAdapterInfo);
        return false;
    }

    // Warning : multibytes or unicode
    pAdapter->m_sName = CStringUtil::s2ws(pAI->AdapterName);
    pAdapter->m_sDesc = CStringUtil::s2ws(pAI->Description);
    pAdapter->m_sPriWins = CStringUtil::s2ws(pAI->PrimaryWinsServer.IpAddress.String);
    pAdapter->m_sSecWins = CStringUtil::s2ws(pAI->SecondaryWinsServer.IpAddress.String);
    pAdapter->m_dwIndex = pAI->Index;
    pAdapter->m_nAdapterType = pAI->Type;
    pAdapter->m_bDhcpUsed = pAI->DhcpEnabled;
    pAdapter->m_bWinsUsed = pAI->HaveWins;
    pAdapter->m_tLeaseObtained = pAI->LeaseObtained;
    pAdapter->m_tLeaseExpires = pAI->LeaseExpires;
    pAdapter->m_sDhcpAddr = CStringUtil::s2ws(pAI->DhcpServer.IpAddress.String);

    pAdapter->m_macAddrInfo.len = pAI->AddressLength;
    for(int i = 0; i < (int)pAdapter->m_macAddrInfo.len; ++i)
    {
        pAdapter->m_macAddrInfo.macAddr[i] = pAI->Address[i];
    }
    
    if(pAI->CurrentIpAddress != NULL)
    {
        pAdapter->m_sCurIpAddr.strIp = CStringUtil::s2ws(pAI->CurrentIpAddress->IpAddress.String);
        pAdapter->m_sCurIpAddr.strSubmask = CStringUtil::s2ws(pAI->CurrentIpAddress->IpAddress.String);
    }
    else
    {
        pAdapter->m_sCurIpAddr.strIp = _T("0.0.0.0");
        pAdapter->m_sCurIpAddr.strSubmask = _T("0.0.0.0");
    }

    IP_ADDR_STRING* pIpNext = &(pAI->IpAddressList);
    while(pIpNext != NULL)
    {
        _tagNetworkAdapterIpInfo iphold;
        iphold.strIp = CStringUtil::s2ws(pIpNext->IpAddress.String);
        iphold.strSubmask = CStringUtil::s2ws(pIpNext->IpAddress.String);
        pAdapter->m_IpAddresses.push_back(iphold);
        pIpNext = pIpNext->Next;
    }

    pIpNext = &(pAI->GatewayList);
    while(pIpNext != NULL)
    {
        pAdapter->m_GatewayList.push_back(CStringUtil::s2ws(pIpNext->IpAddress.String));
        pIpNext = pIpNext->Next;
    }

    IP_PER_ADAPTER_INFO* pPerAdapter = NULL;
    errNum = ::GetPerAdapterInfo(adapterIndex, pPerAdapter, &ulen);
    if(errNum == ERROR_BUFFER_OVERFLOW)
    {
        pPerAdapter = (IP_PER_ADAPTER_INFO*)malloc(ulen);
        errNum = ::GetPerAdapterInfo(adapterIndex, pPerAdapter, &ulen);
        if(errNum == ERROR_SUCCESS)
        {
            pIpNext = &(pPerAdapter->DnsServerList);
            while(pIpNext != NULL)
            {
                pAdapter->m_DnsAddresses.push_back(CStringUtil::s2ws(pIpNext->IpAddress.String));
                pIpNext = pIpNext->Next;
            }
        }

        free(pPerAdapter);
        pPerAdapter = NULL;
    }

    free(pAdapterInfo);
    return true;
}

