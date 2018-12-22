// packer.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include <iostream>
#include<Windows.h>
#include "resource.h"
#include "undoc.h"

using namespace std;

DWORD RunFromMemory(void* pImage);
DWORD Unpack();
void SetDebugger();
void DebugLoop();

DWORD ProcessId;
BOOL GetFxxxx();


int main()
{
	cout << "parent process id : " << GetProcessId(GetCurrentProcess()) << endl;
	if (Unpack() == 1)
	{
		return 0;
	}
	SetDebugger();
	return 0;
}

__forceinline BOOL GetFxxxx()
{
	HMODULE inst = LoadLibrary(L"ntdll.dll");
	if (inst)
	{
		NtQueryInformationProcess = (LPNTQUERYINFORMATIONPROCESS)GetProcAddress(inst, "NtQueryInformationProcess");
		if (!NtQueryInformationProcess)
		{
			printf("OMG\n");
			return FALSE;
		}
		//CloseHandle(inst);
		//printf("x8", NtQueryInformationProcess);
		return TRUE;
	}
	return FALSE;
}


DWORD Unpack() {
	HGLOBAL hResData;
	HRSRC   hResInfo;
	char filename[200];
	void    *pvRes;
	DWORD dwSize;
	char* lpMemory;
	HMODULE hModule = GetModuleHandle(NULL);
	GetModuleFileNameA(hModule, filename, 200);
	
	if (((hResInfo = FindResource(hModule, MAKEINTRESOURCE(RESOURCE), RT_RCDATA)) != NULL) && ((hResData = LoadResource(hModule, hResInfo)) != NULL) && ((pvRes = LockResource(hResData)) != NULL))
	{
		dwSize = SizeofResource(hModule, hResInfo);
		lpMemory = (char*)malloc(dwSize);
		memset(lpMemory, 0, dwSize);
		memcpy(lpMemory, pvRes, dwSize);
	
		RunFromMemory(lpMemory);

		free(lpMemory);
		return 0;
	}
	return 1;
}

// NtUnmapViewOfSection
// Used to unmap a section from a process.
typedef long int (__stdcall* NtUnmapViewOfSectionF)(HANDLE,PVOID);
NtUnmapViewOfSectionF NtUnmapViewOfSection = (NtUnmapViewOfSectionF)GetProcAddress(LoadLibraryA("ntdll.dll"),"NtUnmapViewOfSection");
 
DWORD RunFromMemory(void* pImage)
{
    DWORD dwWritten = 0;
    DWORD dwHeader = 0; 
    DWORD dwImageSize = 0;
    DWORD dwSectionCount = 0;
    DWORD dwSectionSize = 0;
    DWORD firstSection = 0;
    DWORD previousProtection = 0;
    DWORD jmpSize = 0;
 
    IMAGE_NT_HEADERS INH;
    IMAGE_DOS_HEADER IDH;
    IMAGE_SECTION_HEADER Sections[1000];
 
    PROCESS_INFORMATION peProcessInformation;
    STARTUPINFOA peStartUpInformation;
 
    char* pMemory;
    char* pFile;
    char* lfMemory;
	lfMemory = (char *)GetModuleHandle(NULL);
    memcpy(&IDH,lfMemory,sizeof(IDH));
    memcpy(&INH,(void*)((DWORD)lfMemory+IDH.e_lfanew),sizeof(INH));
    DWORD localImageBase = INH.OptionalHeader.ImageBase;
 
    memcpy(&IDH,pImage,sizeof(IDH));
    memcpy(&INH,(void*)((DWORD)pImage+IDH.e_lfanew),sizeof(INH));
         
    dwImageSize = INH.OptionalHeader.SizeOfImage;
    pMemory = (char*)malloc(dwImageSize);
    memset(pMemory,0,dwImageSize);
    pFile = pMemory;
	BOOL debugged = false;

    dwHeader = INH.OptionalHeader.SizeOfHeaders;
    firstSection = (DWORD)(((DWORD)pImage+IDH.e_lfanew) + sizeof(IMAGE_NT_HEADERS));
    memcpy(Sections,(char*)(firstSection),sizeof(IMAGE_SECTION_HEADER)*INH.FileHeader.NumberOfSections);
 
    memcpy(pFile,pImage,dwHeader);
 
    if ((INH.OptionalHeader.SizeOfHeaders % INH.OptionalHeader.SectionAlignment)==0)
        jmpSize = INH.OptionalHeader.SizeOfHeaders;
    else
    {
        jmpSize = INH.OptionalHeader.SizeOfHeaders / INH.OptionalHeader.SectionAlignment;
        jmpSize += 1;
        jmpSize *= INH.OptionalHeader.SectionAlignment;
    }
 
    pFile = (char*)((DWORD)pFile + jmpSize);
 
    for (dwSectionCount = 0; dwSectionCount < INH.FileHeader.NumberOfSections; dwSectionCount++)
    {
        jmpSize = 0;
        dwSectionSize = Sections[dwSectionCount].SizeOfRawData;
        memcpy(pFile,(char *)pImage + Sections[dwSectionCount].PointerToRawData,dwSectionSize);
         
        if((Sections[dwSectionCount].Misc.VirtualSize % INH.OptionalHeader.SectionAlignment)==0)
            jmpSize = Sections[dwSectionCount].Misc.VirtualSize;
        else
        {
            jmpSize = Sections[dwSectionCount].Misc.VirtualSize / INH.OptionalHeader.SectionAlignment;
            jmpSize += 1;
            jmpSize *= INH.OptionalHeader.SectionAlignment;
        }
        pFile = (char*)((DWORD)pFile + jmpSize);
    }
 
	memset(&peStartUpInformation, 0, sizeof(STARTUPINFOA));
	memset(&peProcessInformation, 0, sizeof(PROCESS_INFORMATION));

	peStartUpInformation.cb = sizeof(peStartUpInformation);

	char filename[MAX_PATH];
    GetModuleFileNameA(NULL,filename,MAX_PATH);

    CreateProcessA(NULL,filename,NULL,NULL,0,CREATE_SUSPENDED, NULL,NULL, &peStartUpInformation, &peProcessInformation);

	// delete the original image from the process
    NtUnmapViewOfSection(peProcessInformation.hProcess,(PVOID)(localImageBase));
	// allocate and paste the new image with PAGE_EXECUTE_READWRITE permissions
	VirtualAllocEx(peProcessInformation.hProcess,(LPVOID)(INH.OptionalHeader.ImageBase),dwImageSize,MEM_COMMIT | MEM_RESERVE,PAGE_EXECUTE_READWRITE);
	VirtualProtectEx(peProcessInformation.hProcess,(void*)(INH.OptionalHeader.ImageBase),dwImageSize,PAGE_EXECUTE_READWRITE,0);
	WriteProcessMemory(peProcessInformation.hProcess,(void*)(INH.OptionalHeader.ImageBase),pMemory,dwImageSize,&dwWritten);
	// continue execution from the entry point
	CONTEXT pContext;
    pContext.ContextFlags = CONTEXT_FULL;
    GetThreadContext(peProcessInformation.hThread,&pContext);
    pContext.Eax = INH.OptionalHeader.ImageBase + INH.OptionalHeader.AddressOfEntryPoint;
	SetThreadContext(peProcessInformation.hThread,&pContext);
    ResumeThread(peProcessInformation.hThread);
    
    free(pMemory);

	ProcessId = GetProcessId(peProcessInformation.hProcess);

	return 0;
}


void SetDebugger() {
	if (!DebugActiveProcess(ProcessId))
	{
		printf("DebugActiveProcess(%d) failed!!!\n"
			"Error Code = %d\n", ProcessId, GetLastError());
		return;
	}
	DebugLoop();
}



void DebugLoop() {

	DEBUG_EVENT de;
	DWORD dwContinueStatus;
	
	while (true)
	{
		WaitForDebugEvent(&de, 1000 * 30);
		printf("WaitForDebugEvent timeout\n");
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