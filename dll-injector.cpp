// dll-injector.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <iostream>
#include <windows.h>
#include <tlhelp32.h>

using namespace std;

HANDLE findProcess(WCHAR * processName);
BOOL LoadRemoteDll(HANDLE HostProcess, const char* dllPath, LPVOID startAddr);
LPVOID GetFuncAddr();
void SetDebugger(DWORD ProcessId);
void DebugLoop();

int wmain(int argc, wchar_t *argv[])
{
	cout << "child process id : " << GetProcessId(GetCurrentProcess()) << endl;

	LPVOID StartAddr = GetFuncAddr();
	DWORD pid;
	if (StartAddr != NULL)
	{
		HANDLE host = findProcess((WCHAR*)L"host.exe");
		if (host != NULL)
		{
			pid = GetProcessId(host);
			const char dllPath[MAX_PATH] = "mydll.dll";
			if (LoadRemoteDll(host, dllPath, StartAddr))
			{
				printf("dll injection went well !\n");
			}
			SetDebugger(pid);
			//CloseHandle(host);
		}
	}
	getchar();
	return 0;
}

HANDLE findProcess(WCHAR* processName) {

	HANDLE hProcessSnap;
	HANDLE hProcess;
	PROCESSENTRY32 pe32;
	//DWORD dwPriorityClass;

	// Take a snapshot of all processes in the system.
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE) {
		printf("[---] Could not create snapshot.\n");
	}

	// Set the size of the structure before using it.
	pe32.dwSize = sizeof(PROCESSENTRY32);

	// Retrieve information about the first process,
	// and exit if unsuccessful
	if (!Process32First(hProcessSnap, &pe32)) {
		//printError(TEXT("Process32First"));
		CloseHandle(hProcessSnap);
		return FALSE;
	}

	// Now walk the snapshot of processes, and
	// display information about each process in turn
	do {
		if (wcscmp(pe32.szExeFile, processName) == 0) {
			wprintf(L"[+] The process %s was found in memory.\n", pe32.szExeFile);

			hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
			if (hProcess != NULL) {
				return hProcess;
			}
			else {
				printf("[---] Failed to open process %s.\n", pe32.szExeFile);
				return NULL;

			}
		}
		/*hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
		if (hProcess != NULL) {
			wcout << L"host process found: " << pe32.szExeFile << L"\n";
			return hProcess;
		}*/

	} while (Process32Next(hProcessSnap, &pe32));

	//printf("[---] %s has not been loaded into memory, aborting.\n", processName);
	return NULL;
}


BOOL LoadRemoteDll(HANDLE HostProcess, const char* dllPath, LPVOID startAddr) {

	// Allocate memory for DLL's path name to remote process
	LPVOID dllPathAddressInRemoteMemory = VirtualAllocEx(HostProcess, NULL, strlen(dllPath), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (dllPathAddressInRemoteMemory == NULL) {
		printf("[---] VirtualAllocEx unsuccessful.\n");
		//printError(TEXT("VirtualAllocEx"));
		getchar();
		return FALSE;
	}

	// Write DLL's path name to remote process
	BOOL succeededWriting = WriteProcessMemory(HostProcess, dllPathAddressInRemoteMemory, dllPath, strlen(dllPath), NULL);

	if (!succeededWriting) {
		printf("[---] WriteProcessMemory unsuccessful.\n");
		//printError(TEXT("WriteProcessMemory"));
		getchar();
		return FALSE;
	}
	else {
		HANDLE remoteThread = CreateRemoteThread(HostProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)startAddr, dllPathAddressInRemoteMemory, NULL, NULL);
		if (remoteThread == NULL) {
			printf("[---] CreateRemoteThread unsuccessful.\n");
			//printError(TEXT("CreateRemoteThread"));
			return FALSE;
		}
	}
	CloseHandle(HostProcess);
	return TRUE;
}


LPVOID GetFuncAddr()
{
	HMODULE krnl32dll;
	krnl32dll = GetModuleHandle(L"kernel32.dll");
	if (krnl32dll)
	{
		LPVOID loadLibraryAddress = (LPVOID)GetProcAddress(krnl32dll, "LoadLibraryA");
		if (loadLibraryAddress)
		{			
			return loadLibraryAddress;
		}
	}
	return NULL;
}


void SetDebugger(DWORD ProcessId) {
	if (!DebugActiveProcess(ProcessId))
	{
		printf("DebugActiveProcess failed!!!\n");
		return;
	}
	DebugLoop();
}


void DebugLoop() {

	DEBUG_EVENT de;
	DWORD dwContinueStatus;

	while (true)
	{
		WaitForDebugEvent(&de, INFINITE);

		dwContinueStatus = DBG_CONTINUE;

		if (CREATE_PROCESS_DEBUG_EVENT == de.dwDebugEventCode)
		{
			//DebugActiveProcessStop(ProcessId);
		printf("CREATE_PROCESS_DEBUG_EVENT\n");
		}
		else if (EXIT_PROCESS_DEBUG_EVENT == de.dwDebugEventCode)
		{
			printf("EXIT_PROCESS_DEBUG_EVENT\n");
			break;
		}
		ContinueDebugEvent(de.dwProcessId, de.dwThreadId, dwContinueStatus);
	}
}