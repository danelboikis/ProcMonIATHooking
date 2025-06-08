#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <psapi.h>

#define DLL_NAME _T("APIHooking.dll")

TCHAR fullPath[MAX_PATH]; // will hold the full path of the injected dll
SIZE_T dllNameSize; // size of the full path

// inject dll into remotePid
int inject(int remotePID)
{
	HANDLE hRemoteProcess;
	HANDLE hRemoteThread;
	FARPROC funcAddress;
	HMODULE hKernel32;

	HMODULE hMods[1024];
	DWORD cbNeeded;
	HMODULE hInjectedDLL= NULL;

	// get a handle to the process
	hRemoteProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, remotePID);

	if (!hRemoteProcess)
	{
		_tprintf(_T("error OpenProcess: %d\n"), GetLastError());
		return 1;
	}

	// this code is taken from here: https://learn.microsoft.com/en-us/windows/win32/psapi/enumerating-all-modules-for-a-process
	if (!EnumProcessModules(hRemoteProcess, hMods, sizeof(hMods), &cbNeeded))
	{
		_tprintf(_T("error EnumProcessModules: %d\n"), GetLastError());
		CloseHandle(hRemoteProcess);
		return 1;
	}

	for (int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
	{
		TCHAR szModName[MAX_PATH];

		// Get the full path to the module's file.

		if (GetModuleFileNameEx(hRemoteProcess, hMods[i], szModName,
			sizeof(szModName) / sizeof(TCHAR)))
		{
			if (_tcsicmp(szModName, fullPath) == 0)
			{
				_tprintf(_T("found hmodule!"));
				hInjectedDLL = hMods[i];
				break;
			}
		}
	}

	if (!hInjectedDLL)
	{
		_tprintf(_T("Injected DLL module was not found\n"));
		CloseHandle(hRemoteProcess);
		return 1;
	}

	// get a handle to kernel32.dll
	hKernel32 = GetModuleHandle(_T("kernel32.dll"));
	if (!hKernel32)
	{
		_tprintf(_T("error GetModuleHandle: %d\n"), GetLastError());
		CloseHandle(hRemoteProcess);
		return 1;
	}
	FreeLibrary(hInjectedDLL);
	// get adderss of LoadLibraryW (UNICODE)
	funcAddress = GetProcAddress(hKernel32, "FreeLibrary");
	if (!funcAddress)
	{
		_tprintf(_T("error GetProcAddress: %d\n"), GetLastError());
		CloseHandle(hRemoteProcess);
		return 1;
	}

	// create the remote thread and pass the pointer to the dll path name as a parameter to LoadLibrary
	hRemoteThread = CreateRemoteThread(
		hRemoteProcess,
		NULL,
		0,
		(LPTHREAD_START_ROUTINE)funcAddress,
		hInjectedDLL,
		0,
		NULL
	);

	if (!hRemoteThread)
	{
		_tprintf(_T("error CreateRemoteThread: %d\n"), GetLastError());
		CloseHandle(hRemoteProcess);
		return 1;
	}

	// wait for the remote thread to finish
	DWORD res = WaitForSingleObject(hRemoteThread, INFINITE);

	// _tprintf(_T("Loaded: %d\n"), res);

	if (res != 0)
	{
		_tprintf(_T("something went wrong with the remote thread\n"));
	}

	CloseHandle(hRemoteThread);
	CloseHandle(hRemoteProcess);

	return 0;
}

int _tmain(int argc, _TCHAR* argv[])
{
	DWORD length;
	DWORD remotePID;

	// getting the dll path name
	length = GetCurrentDirectory(MAX_PATH, fullPath); // the dll is placed on the same directory as this process
	if (!length)
	{
		_tprintf(_T("error getting cwd: %d\n"), GetLastError());
		return 1;
	}

	if (fullPath[length - 1] != _T('\\'))
	{
		_tcscat_s(fullPath, MAX_PATH, _T("\\"));
	}

	_tcscat_s(fullPath, MAX_PATH, DLL_NAME);

	dllNameSize = (_tcslen(fullPath) + 1) * sizeof(TCHAR);

	_tprintf(_T("Full dll path: %s\n"), fullPath);

	if (argc > 1) // if pid was passed as a command line parameter
	{
		remotePID = _ttoi(argv[1]);
		if (remotePID == 0)
		{
			_tprintf(_T("invalid PID\n"));
			return 1;
		}
		return inject(remotePID);
	}
	else
	{
		_tprintf(_T("Add PID as a command line argument!\n"));
		return 1;
	}
}