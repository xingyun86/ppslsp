// PpsLsp.h : Include file for standard system include files,
// or project specific include files.

#pragma once

#ifndef UNICODE
#define UNICODE
#endif // !UNICODE
#ifndef _UNICODE
#define _UNICODE
#endif // !_UNICODE

#include <WS2spi.h>
#include <winsock2.h>
#include <process.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <Windows.h>
#include <iostream>
#include <tchar.h>
using namespace std;
#pragma warning(disable:4996)
#pragma comment(lib,"sporder.lib")
#pragma comment(lib, "ws2_32.lib")
#include <sporder.h>
//安装LSP
class installLSP
{
public:
    installLSP()
    {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
        CoCreateGuid(&this->Layered_guid);
        CoCreateGuid(&this->AgreementChain_guid);
    }
    ~installLSP()
    {
        WSACleanup();
    }
public:
    //安装LSP,并安装3个协议链
    BOOL InstallProvider(WCHAR* wszDllPath)  //参数：LSP的DLL的地址
    {
        WCHAR wszLSPName[] = (L"AaronLSP");
        LPWSAPROTOCOL_INFOW pProtoInfo = NULL;
        int nProtocols = 0; //分层协议     取出来的模板
        WSAPROTOCOL_INFOW OriginalProtocolInfo[3]; //数组成员为TCP、UDP、原始的目录入口信息
        DWORD dwOrigCatalogId[3]; //记录入口ID号
        int nArrayCount = 0;      //数组个数索引
        DWORD dwLayeredCatalogId; //分层协议的入口ID号
        int nError;
        pProtoInfo = GetProvider(&nProtocols);
        if (nProtocols < 1 || pProtoInfo == NULL)
            return FALSE;
        BOOL bFindUdp = FALSE;
        BOOL bFindTcp = FALSE;
        BOOL bFindRaw = FALSE;
        for (int i = 0; i < nProtocols; i++)
        {   //查找地址族为AF_INET的协议
            if (pProtoInfo[i].iAddressFamily == AF_INET)
            {
                if (!bFindUdp && pProtoInfo[i].iProtocol == IPPROTO_UDP)
                {
                    memcpy(&OriginalProtocolInfo[nArrayCount], &pProtoInfo[i], sizeof(WSAPROTOCOL_INFOW));
                    //去除XP1_IFS_HANDLES标志,防止提供者返回的句柄是真正的操作系统句柄
                    OriginalProtocolInfo[nArrayCount].dwServiceFlags1 &= (~XP1_IFS_HANDLES);
                    //记录目录入口ID
                    dwOrigCatalogId[nArrayCount++] = pProtoInfo[i].dwCatalogEntryId;
                    bFindUdp = TRUE;
                }
                if (!bFindTcp && pProtoInfo[i].iProtocol == IPPROTO_TCP)
                {
                    memcpy(&OriginalProtocolInfo[nArrayCount], &pProtoInfo[i], sizeof(WSAPROTOCOL_INFOW));
                    //去除XP1_IFS_HANDLES标志,防止提供者返回的句柄是真正的操作系统句柄
                    OriginalProtocolInfo[nArrayCount].dwServiceFlags1 &= (~XP1_IFS_HANDLES);
                    //记录目录入口ID
                    dwOrigCatalogId[nArrayCount++] = pProtoInfo[i].dwCatalogEntryId;
                    bFindTcp = TRUE;
                }
                if (!bFindRaw && pProtoInfo[i].iProtocol == IPPROTO_IP)
                {
                    memcpy(&OriginalProtocolInfo[nArrayCount], &pProtoInfo[i], sizeof(WSAPROTOCOL_INFOW));
                    //去除XP1_IFS_HANDLES标志,防止提供者返回的句柄是真正的操作系统句柄
                    OriginalProtocolInfo[nArrayCount].dwServiceFlags1 &= (~XP1_IFS_HANDLES);
                    //记录目录入口ID
                    dwOrigCatalogId[nArrayCount++] = pProtoInfo[i].dwCatalogEntryId;
                    bFindRaw = TRUE;
                }
            }
        }
        if (nArrayCount == 0)
        {
            FreeProvider(pProtoInfo);
            return FALSE;
        }
        //安装LSP分层协议
        WSAPROTOCOL_INFOW LayeredProtocolInfo;


        memcpy(&LayeredProtocolInfo, &OriginalProtocolInfo[0], sizeof(WSAPROTOCOL_INFOW));
        //修改协议名称的字符串
        wcscpy(LayeredProtocolInfo.szProtocol, wszLSPName);
        //表示分层协议
        LayeredProtocolInfo.ProtocolChain.ChainLen = LAYERED_PROTOCOL;//0
        //表示方式为由提供者自己设置
        LayeredProtocolInfo.dwProviderFlags = PFL_HIDDEN;
        //安装分层协议
        if (SOCKET_ERROR == WSCInstallProvider(&Layered_guid, wszDllPath, &LayeredProtocolInfo, 1, &nError))
        {
            FreeProvider(pProtoInfo);
            return FALSE;
        }
        FreeProvider(pProtoInfo);
        //重新遍历协议,获取分层协议的目录ID号
        pProtoInfo = GetProvider(&nProtocols);
        if (nProtocols < 1 || pProtoInfo == NULL)
            return FALSE;
        for (int i = 0; i < nProtocols; i++)//一般安装新入口后,会排在最低部
        {
            if (memcmp(&pProtoInfo[i].ProviderId, &Layered_guid, sizeof(GUID)) == 0)
            {
                //取出分层协议的目录入口ID
                dwLayeredCatalogId = pProtoInfo[i].dwCatalogEntryId;
                break;
            }
        }
        //安装协议链                 256
        WCHAR wszChainName[WSAPROTOCOL_LEN + 1];//新分层协议的名称  over   取出来的入口模板的名称
        for (int i = 0; i < nArrayCount; i++)
        {
            wsprintf(wszChainName, (L"%s over %s"), wszLSPName, OriginalProtocolInfo[i].szProtocol);
            wcscpy(OriginalProtocolInfo[i].szProtocol, wszChainName);  //将这个模板的名称改成新名称↑
            if (OriginalProtocolInfo[i].ProtocolChain.ChainLen == 1)//这是基础协议的模板
            {   //修改基础协议模板的协议链, 在协议链[1]写入真正UDP[基础协议]的入口ID
                OriginalProtocolInfo[i].ProtocolChain.ChainEntries[1] = dwOrigCatalogId[i];
            }
            else
            {//如果大于1,相当于是个协议链,表示：将协议链中的入口ID,全部向后退一格,留出[0]
                for (int j = OriginalProtocolInfo[i].ProtocolChain.ChainLen; j > 0; j--)
                    OriginalProtocolInfo[i].ProtocolChain.ChainEntries[j] = OriginalProtocolInfo[i].ProtocolChain.ChainEntries[j - 1];
            }
            //让新分层协议排在基础协议的前面（如果为协议链排就排在开头了）
            OriginalProtocolInfo[i].ProtocolChain.ChainLen++;
            OriginalProtocolInfo[i].ProtocolChain.ChainEntries[0] = dwLayeredCatalogId;
        }
        //一次安装3个协议链
        if (SOCKET_ERROR == WSCInstallProvider(&AgreementChain_guid, wszDllPath, OriginalProtocolInfo, nArrayCount, &nError))
        {
            FreeProvider(pProtoInfo);
            return FALSE;
        }
        //第三步：将所有3种协议进行重新排序,以让系统先调用我们的协议（让协议链排第一,协议链中[0]是新分层协议,[1]基础UDP协议）
        //重新遍历所有协议
        FreeProvider(pProtoInfo);
        pProtoInfo = GetProvider(&nProtocols);
        if (nProtocols < 1 || pProtoInfo == NULL)
            return FALSE;
        DWORD dwIds[20];
        int nIndex = 0;
        //添加我们的协议链
        for (int i = 0; i < nProtocols; i++)
        {//如果是我们新创建的协议链
            if (pProtoInfo[i].ProtocolChain.ChainLen > 1 && pProtoInfo[i].ProtocolChain.ChainEntries[0] == dwLayeredCatalogId)
                dwIds[nIndex++] = pProtoInfo[i].dwCatalogEntryId;//将3个协议链排在前3
        }
        //添加其他协议
        for (int i = 0; i < nProtocols; i++)
        {//如果是基础协议,分层协议(不包括我们的协议链,但包括我们的分层协议)
            if (pProtoInfo[i].ProtocolChain.ChainLen <= 1 || pProtoInfo[i].ProtocolChain.ChainEntries[0] != dwLayeredCatalogId)
                dwIds[nIndex++] = pProtoInfo[i].dwCatalogEntryId;
        }
        //重新排序Winsock目录
        if (WSCWriteProviderOrder(dwIds, nIndex) != ERROR_SUCCESS)
            return FALSE;
        FreeProvider(pProtoInfo);
        return TRUE;
    }
    //卸载LSP
    void RemoveProvider()
    {
        LPWSAPROTOCOL_INFOW pProtoInfo = NULL;
        int nProtocols = 0;
        DWORD dwLayeredCatalogId = 0; //分层协议提供者的入口ID号
         //遍历出所有协议
        pProtoInfo = GetProvider(&nProtocols);
        if (nProtocols < 1 || pProtoInfo == NULL)
            return;
        int nError = 0;
        int i = 0;
        for (i = 0; i < nProtocols; i++)
        { //查找分层协议提供者
            if (memcmp(&Layered_guid, &pProtoInfo[i].ProviderId, sizeof(GUID)) == 0)
            {
                dwLayeredCatalogId = pProtoInfo[i].dwCatalogEntryId;
                break;
            }
        }
        if (i < nProtocols)
        {
            for (i = 0; i < nProtocols; i++)
            {//查找协议链(这个协议链的[0]为分层协议提供者)
                if (pProtoInfo[i].ProtocolChain.ChainLen > 1 && pProtoInfo[i].ProtocolChain.ChainEntries[0] == dwLayeredCatalogId)
                {//先卸载协议链
                    WSCDeinstallProvider(&pProtoInfo[i].ProviderId, &nError);
                    break;
                }
            }
            WSCDeinstallProvider(&Layered_guid, &nError);
        }
    }
private:
    //这两个函数是遍历所有协议函数,在编写DLL时,已经把源代码放出来了,这里就不放出来了.
    LPWSAPROTOCOL_INFOW GetProvider(LPINT lpnTotalProtocols)
    {
        //遍历所有协议
        int nError = 0;
        DWORD dwSize = 0;
        LPWSAPROTOCOL_INFOW pProtoInfo = NULL;
        if (WSCEnumProtocols(NULL, pProtoInfo, &dwSize, &nError) == SOCKET_ERROR)
        {
            if (nError != WSAENOBUFS)
                return NULL;
        }
        pProtoInfo = (LPWSAPROTOCOL_INFOW)new WSAPROTOCOL_INFOW[dwSize / sizeof(WSAPROTOCOL_INFOW)];
        if (!pProtoInfo)
            return NULL;
        ZeroMemory(pProtoInfo, dwSize);
        *lpnTotalProtocols = WSAEnumProtocols(NULL, pProtoInfo, &dwSize);
        return pProtoInfo;
    }
    void FreeProvider(LPWSAPROTOCOL_INFOW pProtoInfo)
    {
        delete[] pProtoInfo;
    }
private:
    GUID Layered_guid;        //分层协议GUID
    GUID AgreementChain_guid; //协议链GUID
};

#define PATH _T("LSPDll.dll")
SOCKET server_tcp = NULL;
SOCKET server_udp = NULL;
SOCKET client_tcp = NULL;
SOCKET client_udp = NULL;
int main(int argc, char** argv)
{
    system("color 4e");
    SetConsoleTitle(_T("安装LSP提供者程序实验"));
    //ProtocolTraversestheExperiment2 s;
    printf("安装LSP前的所有协议:\r\n");
    //s.ShowAllProtocol();
    installLSP LSP;
    LSP.InstallProvider(PATH);
    printf("安装LSP后的所有协议:\r\n");
    //s.ShowAllProtocol();
    getchar();
    LSP.RemoveProvider();
    printf("清除LSP完成\r\n");
    getchar();
    return 0;
}