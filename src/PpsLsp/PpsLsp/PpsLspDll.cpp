// PpsLsp.h : Include file for standard system include files,
// or project specific include files.

#pragma once

#ifndef UNICODE
#define UNICODE
#endif // !UNICODE
#ifndef _UNICODE
#define _UNICODE
#endif // !_UNICODE

#include <winsock2.h>
#include <ws2spi.h>
#include <tchar.h>


int WSPAPI WSPConnect(       //自定义的WSPConnect函数
    SOCKET s,
    const struct sockaddr FAR* name,
    int namelen,
    LPWSABUF lpCallerData,
    LPWSABUF lpCalleeData,
    LPQOS lpSQOS,
    LPQOS lpGQOS,
    LPINT lpErrno
);
int WSPAPI WSPSendTo         //自定义的WSPSendTo函数
(
    SOCKET s,
    LPWSABUF lpBuffers,
    DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesSent,
    DWORD dwFlags,
    const struct sockaddr FAR* lpTo,
    int iTolen,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,
    LPWSATHREADID lpThreadId,
    LPINT lpErrno
);

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

WSPPROC_TABLE g_NextProcTable;  //下层提供者的函数表        全局

//LSP的初始化函数（唯一的导出函数）

int WSPAPI WSPStartup(
    WORD wVersionRequested,                          //用户程序加载套接字库的版本号(in)
    LPWSPDATA lpWSPData,                               //用于取得Winsock服务的详细信息
    LPWSAPROTOCOL_INFO lpProtocolInfo,   //指定想得到的协议的特征
    WSPUPCALLTABLE UpcallTable,                 //Ws2_32.dll向上调用转发的函数表
    LPWSPPROC_TABLE lpProTable                 //下层提供者的函数表（一般为基础协议,共30个服务函数）
)
{   //如果协议位分层协议或基础协议,那么返回错误
    if (lpProtocolInfo->ProtocolChain.ChainLen <= 1)
    {   //无法加载或初始化请求的服务提供程序
        return WSAEPROVIDERFAILEDINIT;
    }

    //找到下层协议的WSAPROTOCOL_INFOW结构体
    WSAPROTOCOL_INFOW NextProtocolInfo;
    int nTotalProtols;
    LPWSAPROTOCOL_INFOW pProtoInfo = GetProvider(&nTotalProtols);
    //下层提供者的入口ID
    DWORD dwBaseEntryId = lpProtocolInfo->ProtocolChain.ChainEntries[1];
    //遍历所有协议
    int i = 0;
    for (; i < nTotalProtols; i++)
    {//找到下层提供者协议
        if (pProtoInfo[i].dwCatalogEntryId == dwBaseEntryId)
        {
            memcpy(&NextProtocolInfo, &pProtoInfo[i], sizeof(WSAPROTOCOL_INFOW));
            break;
        }
    }
    //如果没找到
    if (i >= nTotalProtols)
        return WSAEPROVIDERFAILEDINIT;
    //加载下层协议的Dll
    int nError = 0;
    TCHAR szBaseProviderDll[MAX_PATH];
    int nLen = MAX_PATH;
    //取得下层提供者的DLL路径（可能包含坏境变量）
    if (WSCGetProviderPath(&NextProtocolInfo.ProviderId, szBaseProviderDll, &nLen, &nError) == SOCKET_ERROR)
        return WSAEPROVIDERFAILEDINIT;
    //坏境变量转换字符串
    if (!ExpandEnvironmentStrings(szBaseProviderDll, szBaseProviderDll, MAX_PATH))
        return WSAEPROVIDERFAILEDINIT;
    //加载dll
    HMODULE hModdule = LoadLibrary(szBaseProviderDll);
    if (hModdule == NULL)
        return WSAEPROVIDERFAILEDINIT;
    //取出下层提供者的WSPStartup函数
    LPWSPSTARTUP pfnWSPStartup = (LPWSPSTARTUP)GetProcAddress(hModdule, "WSPStartup");
    if (NULL == pfnWSPStartup)
        return WSAEPROVIDERFAILEDINIT;
    LPWSAPROTOCOL_INFOW pInfo = lpProtocolInfo;
    if (NextProtocolInfo.ProtocolChain.ChainLen == BASE_PROTOCOL)//如果下层提供者是基础协议
        pInfo = &NextProtocolInfo;                               //赋给pInfo指针
        //调用下层提供者的初始化函数
    int nRet = pfnWSPStartup(wVersionRequested, lpWSPData, lpProtocolInfo, UpcallTable, lpProTable);
    //初始化失败
    if (nRet != ERROR_SUCCESS)
        return nRet;

    //初始化完成后,复制下层提供者(基础协议)的整个函数表
    g_NextProcTable = *lpProTable;
    //将基础协议的SendTo函数指针,指向我们的WSPSendTo函数,在我们的函数内,再确定要不要调用回基础协议的Sendto函数
    lpProTable->lpWSPSendTo = WSPSendTo;
    lpProTable->lpWSPConnect = WSPConnect;
    FreeProvider(pProtoInfo);
    return nRet;
}

//下面对sendto、connect函数的8888端口进行拦截：

int WSPAPI WSPConnect(       //自定义的WSPConnect函数
    SOCKET s,
    const struct sockaddr FAR* name,
    int namelen,
    LPWSABUF lpCallerData,
    LPWSABUF lpCalleeData,
    LPQOS lpSQOS,
    LPQOS lpGQOS,
    LPINT lpErrno
)
{
    sockaddr_in* info = (sockaddr_in*)name;
    USHORT port = ntohs(info->sin_port);
    if (port == 8888)   //如果是8888端口,那么拦截
    {
        int nError = 0;

        //因为整个dll已经加载进程序里,这里对我的控制台程序进行测试
        SetConsoleTitle(_T("sorry,we shutdown you tcp protocol port<8888>!"));
        g_NextProcTable.lpWSPShutdown(s, SD_BOTH, &nError);
        //设置错误信息
        *lpErrno = WSAECONNABORTED;
        return SOCKET_ERROR;
    }

    //如果不是,调用下层提供者的函数表中的WSPConnect函数
    return g_NextProcTable.lpWSPConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS, lpErrno);
}
int WSPAPI WSPSendTo         //自定义的WSPSendTo函数
(
    SOCKET s,
    LPWSABUF lpBuffers,
    DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesSent,
    DWORD dwFlags,
    const struct sockaddr FAR* lpTo,
    int iTolen,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,
    LPWSATHREADID lpThreadId,
    LPINT lpErrno
)
{
    sockaddr_in* info = (sockaddr_in*)lpTo;
    USHORT port = ntohs(info->sin_port);
    if (port == 8888)    //如果是8888端口,那么拦截
    {
        int nError = 0;
        SetConsoleTitle(_T("sorry,we shutdown you udp protocol port<8888>!"));
        g_NextProcTable.lpWSPShutdown(s, SD_BOTH, &nError);
        //设置错误信息
        *lpErrno = WSAECONNABORTED;
        return SOCKET_ERROR;
    }

    //如果不是,调用下层提供者的函数表中的WSPSendTo函数
    return g_NextProcTable.lpWSPSendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags,
        lpTo, iTolen, lpOverlapped, lpCompletionRoutine, lpThreadId, lpErrno);
}
