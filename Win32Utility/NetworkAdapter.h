/** 
    Author: Morgan.Li
    Date: 2018.10.18
*/

#ifndef __NETWORKADAPTER_H__
#define __NETWORKADAPTER_H__

#include "Type.h"
#include "Export.h"

struct _tagNetworkAdapterIpInfo
{
    tstring    strIp;
    tstring    strSubmask;
};

struct _tagNetworkAdapterMacAddress
{
    unsigned char macAddr[8];
    int len;    // MAC address length is 6 normally, but maybe 8
};

/** Network Interface (Adapter) Information and Configrue
*/

class UTILITY_API CNetworkAdapter
{
public:
    explicit CNetworkAdapter(int adapterIndex);
    ~CNetworkAdapter();

public:
    /** A primary adapter is a physical adapter and the adapter index is smallest
    */
    static int FindPrimaryAdapter();
    static bool ObtainAllAdapterIndex(std::vector<int>& indexArr);
    /** initialize the adapter information, eg. ip,mac,gateway ip, dns
    */
    static bool SetupAdapter(CNetworkAdapter* pAdapter);

public:
    int GetIndex()
    {
        return m_dwIndex;
    }

private:
    tstring			m_sName;		// adapter name with the computer.  For human readable name use m_sDesc.
    tstring			m_sDesc;
    tstring			m_sPriWins;
    tstring			m_sSecWins;
    tstring			m_sDefGateway;
    tstring			m_sDhcpAddr;
    _tagNetworkAdapterIpInfo			m_sCurIpAddr;	// this is also in the ip address list but this is the address currently active.
    int			m_dwIndex;		// machine index of the adapter.
    int			m_nAdapterType;
    bool			m_bDhcpUsed;
    bool			m_bWinsUsed;
    std::vector<tstring>		m_DnsAddresses;
    std::vector<_tagNetworkAdapterIpInfo>   m_IpAddresses;
    std::vector<tstring>		m_GatewayList;
    time_t			m_tLeaseObtained;
    time_t			m_tLeaseExpires;
    _tagNetworkAdapterMacAddress    m_macAddrInfo;
};

#endif  // __NETWORKADAPTER_H__
