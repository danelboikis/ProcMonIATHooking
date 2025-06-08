#include <windows.h>
#include <tchar.h>
#include <stdio.h>


TCHAR fullPath[MAX_PATH]; // will hold the full path of the injected dll
SIZE_T dllNameSize; // size of the full path

// inject dll into remotePid
int inject(int remotePID)
{
	HANDLE hRemoteProcess;
	LPVOID remoteAddress;
	HANDLE hRemoteThread;
	FARPROC funcAddress;
	HMODULE hKernel32;

	// get a handle to the process
	hRemoteProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, remotePID);

	if (!hRemoteProcess)
	{
		_tprintf(_T("error OpenProcess: %d\n"), GetLastError());
		return 1;
	}

	// allocating space on the remote process to write the dll path name
	remoteAddress = VirtualAllocEx(
		hRemoteProcess,
		NULL,
		dllNameSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	);

	if (!remoteAddress)
	{
		_tprintf(_T("error VirtualAllocEx: %d\n"), GetLastError());
		return 1;
	}

	// write the dll path name at the allocated space
	if (!WriteProcessMemory(hRemoteProcess, remoteAddress, fullPath, dllNameSize, NULL))
	{
		_tprintf(_T("error WriteProcessMemory: %d\n"), GetLastError());
		return 1;
	}

	// get a handle to kernel32.dll
	hKernel32 = GetModuleHandle(_T("kernel32.dll"));
	if (!hKernel32)
	{
		_tprintf(_T("error GetModuleHandle: %d\n"), GetLastError());
		return 1;
	}

	// get adderss of LoadLibraryW (UNICODE)
	funcAddress = GetProcAddress(hKernel32, "LoadLibraryW");
	if (!funcAddress)
	{
		_tprintf(_T("error GetProcAddress: %d\n"), GetLastError());
		return 1;
	}



	// create the remote thread and pass the pointer to the dll path name as a parameter to LoadLibrary
	hRemoteThread = CreateRemoteThread(
		hRemoteProcess,
		NULL,
		0,
		(LPTHREAD_START_ROUTINE)funcAddress,
		remoteAddress,
		0,
		NULL
	);

	if (!hRemoteThread)
	{
		_tprintf(_T("error CreateRemoteThread: %d\n"), GetLastError());
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
	TCHAR* dllName = _T("APIHooking.dll");
	//TCHAR* dllName = _T("hideInject.dll");
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

	_tcscat_s(fullPath, MAX_PATH, dllName);


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