// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include <Windows.h>
#include <tlhelp32.h>
#include <iostream>
#include<string>

using namespace std;

DWORD findProcess(WCHAR* processName);
void SetDebugger(DWORD ProcessId);
void DebugLoop();


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
	DWORD processId;
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		processId = findProcess((WCHAR*)L"packer.exe");
		MessageBoxA(NULL, &to_string(processId)[0], "we found the relevant pid", MB_OK);
		if (processId != NULL)
		{
			SetDebugger(processId);
		}
		break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

DWORD findProcess(WCHAR* processName) {

	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;
	//DWORD dwPriorityClass;

	// Take a snapshot of all processes in the system.
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE) {
		MessageBox(NULL, L"[---] Could not create snapshot.\n", L" ", MB_OK);
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
		if (wcscmp(pe32.szExeFile, processName) == 0 && pe32.th32ParentProcessID != 1604) {
			MessageBox(NULL, L"[+] The parent process was found in memory.\n", L"message from dll", MB_OK);
			/*hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
			if (hProcess != NULL) {
				return hProcess;
			}
			else {
				printf("[---] Failed to open process %s.\n", pe32.szExeFile);
				return NULL;

			}*/
			return pe32.th32ProcessID;
		}
	
	} while (Process32Next(hProcessSnap, &pe32));

	MessageBox(NULL, L"the process has not been loaded into memory, aborting.\n", L" ", MB_OK);
	return NULL;
}

void SetDebugger(DWORD ProcessId) {
	DWORD le;
	if (!DebugActiveProcess(ProcessId))
	{
		le = GetLastError();
		MessageBoxA(NULL, &to_string(le)[0], "DebugActiveProcess failed!!!", MB_OK);
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
			MessageBox(NULL, L"CREATE_PROCESS_DEBUG_EVENT\n", L" ", MB_OK);
		}
		else if (EXIT_PROCESS_DEBUG_EVENT == de.dwDebugEventCode)
		{
			MessageBox(NULL, L"EXIT_PROCESS_DEBUG_EVENT\n", L" ", MB_OK);
			break;
		}
		ContinueDebugEvent(de.dwProcessId, de.dwThreadId, dwContinueStatus);
	}
}