#include "pch.h"
#include "Utils.h"

BOOL IsWoW64()
{
	BOOL bIsWow64 = FALSE;
	
	if (API::IsAvailable(API_IDENTIFIER::API_IsWow64Process))
	{
		auto fnIsWow64Process = static_cast<pIsWow64Process>(API::GetAPI(API_IDENTIFIER::API_IsWow64Process));
		if (!fnIsWow64Process(GetCurrentProcess(), &bIsWow64))
		{
			// handle error
		}
	}

	return bIsWow64;
}

PVOID64 GetPeb64()
{
	PVOID64 peb64 = NULL;

	if (API::IsAvailable(API_IDENTIFIER::API_NtWow64QueryInformationProcess64))
	{
		PROCESS_BASIC_INFORMATION_WOW64 pbi64 = {};

		auto NtWow64QueryInformationProcess64 = static_cast<pNtWow64QueryInformationProcess64>(API::GetAPI(API_IDENTIFIER::API_NtWow64QueryInformationProcess64));
		NTSTATUS status = NtWow64QueryInformationProcess64(GetCurrentProcess(), ProcessBasicInformation, &pbi64, sizeof(pbi64), nullptr);
		if ( NT_SUCCESS ( status ) )
			peb64 = pbi64.PebBaseAddress;
	}

	return peb64;
}

BOOL Is_RegKeyValueExists(HKEY hKey, const TCHAR* lpSubKey, const TCHAR* lpValueName, const TCHAR* search_str)
{
	HKEY hkResult = NULL;
	TCHAR lpData[1024] = { 0 };
	DWORD cbData = MAX_PATH;

	if (RegOpenKeyEx(hKey, lpSubKey, NULL, KEY_READ, &hkResult) == ERROR_SUCCESS)
	{
		if (RegQueryValueEx(hkResult, lpValueName, NULL, NULL, (LPBYTE)lpData, &cbData) == ERROR_SUCCESS)
		{
			if (StrStrI((PCTSTR)lpData, search_str) != NULL)
			{
				RegCloseKey(hkResult);
				return TRUE;
			}
		}
		RegCloseKey(hkResult);
	}
	return FALSE;

}

BOOL Is_RegKeyExists(HKEY hKey, const TCHAR* lpSubKey)
{
	HKEY hkResult = NULL;
	TCHAR lpData[1024] = { 0 };
	DWORD cbData = MAX_PATH;

	if (RegOpenKeyEx(hKey, lpSubKey, NULL, KEY_READ, &hkResult) == ERROR_SUCCESS)
	{
		RegCloseKey(hkResult);
		return TRUE;
	}

	return FALSE;
}

BOOL is_FileExists(TCHAR* szPath)
{
	DWORD dwAttrib = GetFileAttributes(szPath);
	return (dwAttrib != INVALID_FILE_ATTRIBUTES) && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY);
}

BOOL is_DirectoryExists(TCHAR* szPath)
{
	DWORD dwAttrib = GetFileAttributes(szPath);
	return (dwAttrib != INVALID_FILE_ATTRIBUTES) && (dwAttrib & FILE_ATTRIBUTE_DIRECTORY);
}

BOOL check_mac_addr(const TCHAR* szMac)
{
	BOOL bResult = FALSE;
	PIP_ADAPTER_INFO pAdapterInfo, pAdapterInfoPtr;
	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);

	pAdapterInfo = (PIP_ADAPTER_INFO)MALLOC(sizeof(IP_ADAPTER_INFO));
	if (pAdapterInfo == NULL)
	{
		_tprintf(_T("Error allocating memory needed to call GetAdaptersinfo.\n"));
		return -1;
	}

	DWORD dwResult = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen);

	// Make an initial call to GetAdaptersInfo to get the necessary size into the ulOutBufLen variable
	if (dwResult == ERROR_BUFFER_OVERFLOW)
	{
		FREE(pAdapterInfo);
		pAdapterInfo = (PIP_ADAPTER_INFO)MALLOC(ulOutBufLen);
		if (pAdapterInfo == NULL) {
			printf("Error allocating memory needed to call GetAdaptersinfo\n");
			return 1;
		}

		// Now, we can call GetAdaptersInfo
		dwResult = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen);
	}

	if (dwResult == ERROR_SUCCESS)
	{
		// Convert the given mac address to an array of multibyte chars so we can compare.
		CHAR szMacMultiBytes[4];
		for (int i = 0; i < 4; i++) {
			szMacMultiBytes[i] = (CHAR)szMac[i];
		}

		pAdapterInfoPtr = pAdapterInfo;

		while (pAdapterInfoPtr)
		{

			if (pAdapterInfoPtr->AddressLength == 6 && !memcmp(szMacMultiBytes, pAdapterInfoPtr->Address, 3))
			{
				bResult = TRUE;
				break;
			}
			pAdapterInfoPtr = pAdapterInfoPtr->Next;
		}
	}

	FREE(pAdapterInfo);

	return bResult;
}

BOOL check_adapter_name(const TCHAR* szName)
{
	BOOL bResult = FALSE;
	PIP_ADAPTER_INFO pAdapterInfo, pAdapterInfoPtr;
	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);

	WCHAR *pwszConverted;

	pAdapterInfo = (PIP_ADAPTER_INFO)MALLOC(sizeof(IP_ADAPTER_INFO));
	if (pAdapterInfo == NULL)
	{
		_tprintf(_T("Error allocating memory needed to call GetAdaptersinfo.\n"));
		return -1;
	}

	// Make an initial call to GetAdaptersInfo to get the necessary size into the ulOutBufLen variable

	DWORD dwResult = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen);

	if (dwResult == ERROR_BUFFER_OVERFLOW)
	{
		FREE(pAdapterInfo);
		pAdapterInfo = (PIP_ADAPTER_INFO)MALLOC(ulOutBufLen);
		if (pAdapterInfo == NULL) {
			printf("Error allocating memory needed to call GetAdaptersinfo\n");
			return 1;
		}

		dwResult = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen);
	}

	if (dwResult == ERROR_SUCCESS)
	{
		pAdapterInfoPtr = pAdapterInfo;

		while (pAdapterInfoPtr)
		{
			pwszConverted = ascii_to_wide_str(pAdapterInfoPtr->Description);
			if (pwszConverted) {
				if (StrCmpI(pwszConverted, szName) == 0)
				{
					bResult = TRUE;
				}
				free(pwszConverted);

				if (bResult)
					break;
			}
			pAdapterInfoPtr = pAdapterInfoPtr->Next;
		}
	}

	FREE(pAdapterInfo);

	return bResult;
}

DWORD GetProccessIDByName(TCHAR* szProcessNameTarget)
{
	DWORD processIds[1024];
	DWORD dBytesReturned;
	BOOL bStatus;
	HMODULE hMod;
	DWORD cbNeeded;
	TCHAR szProcessName[MAX_PATH] = _T("");

	// Get the list of process identifiers.
	bStatus = EnumProcesses(processIds, sizeof(processIds), &dBytesReturned);
	if (!bStatus)
	{
		// Something bad happened
	}

	// Calculate how many process identifiers were returned.
	int cProcesses = dBytesReturned / sizeof(DWORD);

	for (int i = 0; i < cProcesses; i++)
	{
		// Get a handle to the process.
		HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processIds[i]);

		// Get the process name.
		if (hProcess != NULL)
		{
			EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded);
			GetModuleBaseName(hProcess, hMod, szProcessName, sizeof(szProcessName) / sizeof(TCHAR));

			CloseHandle(hProcess);

			// Make the comparaison
			if (StrCmpI(szProcessName, szProcessNameTarget) == 0)
				return processIds[i];

		}

		_tprintf(TEXT("%s  (PID: %u)\n"), szProcessName, processIds[i]);
	}

	return FALSE;
}

BOOL SetPrivilege(
	HANDLE hToken,          // token handle
	LPCTSTR Privilege,      // Privilege to enable/disable
	BOOL bEnablePrivilege   // TRUE to enable.  FALSE to disable
)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;
	TOKEN_PRIVILEGES tpPrevious;
	DWORD cbPrevious = sizeof(TOKEN_PRIVILEGES);

	if (!LookupPrivilegeValue(NULL, Privilege, &luid))
		return FALSE;

	/* first pass.  get current privilege setting */
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = 0;

	AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		&tpPrevious,
		&cbPrevious
	);

	if (GetLastError() != ERROR_SUCCESS) return FALSE;

	// 
	// second pass.  set privilege based on previous setting
	// 
	tpPrevious.PrivilegeCount = 1;
	tpPrevious.Privileges[0].Luid = luid;

	if (bEnablePrivilege) {
		tpPrevious.Privileges[0].Attributes |= (SE_PRIVILEGE_ENABLED);
	}
	else {
		tpPrevious.Privileges[0].Attributes ^= (SE_PRIVILEGE_ENABLED &
			tpPrevious.Privileges[0].Attributes);
	}

	AdjustTokenPrivileges(hToken, FALSE, &tpPrevious, cbPrevious, NULL, NULL);

	if (GetLastError() != ERROR_SUCCESS) return FALSE;

	return TRUE;
}


BOOL SetDebugPrivileges(VOID) {
	TOKEN_PRIVILEGES priv = { 0 };
	HANDLE hToken = NULL;
	BOOL bResult = FALSE;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		print_last_error(_T("OpenProcessToken"));
		return bResult;
	}

	priv.PrivilegeCount = 1;
	priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid)) {
		
		bResult = AdjustTokenPrivileges(hToken, FALSE, &priv, 0, NULL, NULL);
		if (!bResult) {
			print_last_error(_T("AdjustTokenPrivileges"));
		}
	}
	else {
		print_last_error(_T("LookupPrivilegeValue"));
	}

	CloseHandle(hToken);
	return bResult;
}

DWORD GetProcessIdFromName(LPCTSTR szProcessName)
{
	PROCESSENTRY32 pe32;
	HANDLE hSnapshot = NULL;
	SecureZeroMemory(&pe32, sizeof(PROCESSENTRY32));

	// We want a snapshot of processes
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	// Check for a valid handle, in this case we need to check for
	// INVALID_HANDLE_VALUE instead of NULL
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		print_last_error(_T("CreateToolhelp32Snapshot"));
		return 0;
	}

	// Now we can enumerate the running process, also 
	// we can't forget to set the PROCESSENTRY32.dwSize member
	// otherwise the following functions will fail
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(hSnapshot, &pe32) == FALSE)
	{
		// Cleanup the mess
		print_last_error(_T("Process32First"));
		CloseHandle(hSnapshot);
		return 0;
	}

	// Do our first comparison
	if (StrCmpI(pe32.szExeFile, szProcessName) == 0)
	{
		// Cleanup the mess
		CloseHandle(hSnapshot);
		return pe32.th32ProcessID;
	}

	// Most likely it won't match on the first try so 
	// we loop through the rest of the entries until
	// we find the matching entry or not one at all
	while (Process32Next(hSnapshot, &pe32))
	{
		if (StrCmpI(pe32.szExeFile, szProcessName) == 0)
		{
			// Cleanup the mess
			CloseHandle(hSnapshot);
			return pe32.th32ProcessID;
		}
	}

	// If we made it this far there wasn't a match, so we'll return 0
	// _tprintf(_T("\n-> Process %s is not running on this system ..."), szProcessName);

	CloseHandle(hSnapshot);
	return 0;
}

DWORD GetMainThreadId(DWORD pid)
{
	/* Get main thread id from process id */
	HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (h != INVALID_HANDLE_VALUE) {
		THREADENTRY32 te;
		te.dwSize = sizeof(te);
		if (Thread32First(h, &te))
		{
			do
			{
				if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(te.th32OwnerProcessID)) {
					if (te.th32OwnerProcessID == pid) {
						HANDLE hThread = OpenThread(READ_CONTROL, FALSE, te.th32ThreadID);
						if (!hThread)
							print_last_error(_T("OpenThread"));
						else {
							CloseHandle(hThread);
							CloseHandle(h);
							return te.th32ThreadID;
						}
					}
				}

			} while (Thread32Next(h, &te));
		}
		CloseHandle(h);
	}

	print_last_error(_T("CreateToolhelp32Snapshot"));
	return (DWORD)0;
}

BOOL InitWMI(IWbemServices **pSvc, IWbemLocator **pLoc, const TCHAR* szNetworkResource)
{
	// Initialize COM.
	HRESULT hres;
	hres = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hres)) {
		print_last_error(_T("CoInitializeEx"));
		return 0;
	}

	// Set general COM security levels
	hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
	if (FAILED(hres)) {
		print_last_error(_T("CoInitializeSecurity"));
		CoUninitialize();
		return 0;
	}

	// Obtain the initial locator to WMI 
	hres = CoCreateInstance(CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(pLoc));
	if (FAILED(hres)) {
		print_last_error(_T("CoCreateInstance"));
		CoUninitialize();
		return 0;
	}

	BSTR strNetworkResource = SysAllocString(szNetworkResource);
	if (strNetworkResource) {

		// Connect to the root\cimv2 namespace 
		hres = (*pLoc)->ConnectServer(strNetworkResource, NULL, NULL, NULL, WBEM_FLAG_CONNECT_USE_MAX_WAIT, 0, 0, pSvc);
		if (FAILED(hres)) {
			SysFreeString(strNetworkResource);
			print_last_error(_T("ConnectServer"));
			(*pLoc)->Release();
			CoUninitialize();
			return 0;
		}
		SysFreeString(strNetworkResource);
	}

	// Set security levels on the proxy -------------------------
	hres = CoSetProxyBlanket(*pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
	if (FAILED(hres))
	{
		print_last_error(_T("CoSetProxyBlanket"));
		(*pSvc)->Release();
		(*pLoc)->Release();
		CoUninitialize();
		return 0;
	}

	return 1;
}

BOOL ExecWMIQuery(IWbemServices **pSvc, IWbemLocator **pLoc, IEnumWbemClassObject **pEnumerator, const TCHAR* szQuery)
{
	// Execute WMI query
	BSTR strQueryLanguage = SysAllocString(OLESTR("WQL"));
	BSTR strQuery = SysAllocString(szQuery);

	BOOL bQueryResult = TRUE;

	if (strQueryLanguage && strQuery) {

		HRESULT hres = (*pSvc)->ExecQuery(strQueryLanguage, strQuery,
			WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
			NULL, pEnumerator);

		if (FAILED(hres)) {
			bQueryResult = FALSE;
			print_last_error(_T("ExecQuery"));
			(*pSvc)->Release();
			(*pLoc)->Release();
			CoUninitialize();
		}

	}

	if (strQueryLanguage) SysFreeString(strQueryLanguage);
	if (strQuery) SysFreeString(strQuery);

	return bQueryResult;
}


ULONG get_idt_base()
{
	// Get the base of Interupt Descriptor Table (IDT)

	UCHAR idtr[6];
	ULONG idt = 0;

	// sidt instruction stores the contents of the IDT Register
	// (the IDTR which points to the IDT) in a processor register.

#if defined (ENV32BIT)
	_asm sidt idtr
#endif
	idt = *((unsigned long *)&idtr[2]);
	// printf("IDT base: 0x%x\n", idt);

	return idt;
}


ULONG get_ldt_base()
{
	// Get the base of Local Descriptor Table (LDT)

	UCHAR ldtr[5] = "\xef\xbe\xad\xde";
	ULONG ldt = 0;

	// sldt instruction stores the contents of the LDT Register
	// (the LDTR which points to the LDT) in a processor register.
#if defined (ENV32BIT)
	_asm sldt ldtr
#endif
	ldt = *((unsigned long *)&ldtr[0]);
	// printf("LDT base: 0x%x\n", ldt);

	return ldt;
}


ULONG get_gdt_base()
{
	// Get the base of Global Descriptor Table (GDT)

	UCHAR gdtr[6];
	ULONG gdt = 0;

	// sgdt instruction stores the contents of the GDT Register
	// (the GDTR which points to the GDT) in a processor register.
#if defined (ENV32BIT)
	_asm sgdt gdtr
#endif
	gdt = *((unsigned long *)&gdtr[2]);
	// printf("GDT base: 0x%x\n", gdt);

	return gdt;
}


/*
Check if a process is running with admin rights
*/
BOOL IsElevated()
{
	BOOL fRet = FALSE;
	HANDLE hToken = NULL;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
		TOKEN_ELEVATION Elevation;
		DWORD cbSize = sizeof(TOKEN_ELEVATION);
		if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
			fRet = Elevation.TokenIsElevated;
		}
	}
	if (hToken) {
		CloseHandle(hToken);
	}
	return fRet;
}


BOOL find_str_in_data(PBYTE needle, size_t needleLen, PBYTE haystack, size_t haystackLen)
{
	for (size_t i = 0; i < haystackLen - needleLen; i++)
	{
		if (memcmp(&haystack[i], needle, needleLen) == 0)
		{
			return TRUE;
		}
	}
	return FALSE;
}


UINT enum_system_firmware_tables(DWORD FirmwareTableProviderSignature, PVOID pFirmwareTableBuffer, DWORD BufferSize)
{
	if (!API::IsAvailable(API_IDENTIFIER::API_EnumSystemFirmwareTables))
	{
		return -1;
	}

	auto EnumSystemFirmwareTables = static_cast<pEnumSystemFirmwareTables>(API::GetAPI(API_IDENTIFIER::API_EnumSystemFirmwareTables));
	return EnumSystemFirmwareTables(FirmwareTableProviderSignature, pFirmwareTableBuffer, BufferSize);
}

PBYTE get_system_firmware(_In_ DWORD signature, _In_ DWORD table, _Out_ PDWORD pBufferSize)
{
	if (!API::IsAvailable(API_IDENTIFIER::API_GetSystemFirmwareTable))
	{
		return NULL;
	}

	DWORD bufferSize = 4096;
	PBYTE firmwareTable = static_cast<PBYTE>(malloc(bufferSize));

	if (firmwareTable == NULL)
		return NULL;

	SecureZeroMemory(firmwareTable, bufferSize);
	
	auto GetSystemFirmwareTable = static_cast<pGetSystemFirmwareTable>(API::GetAPI(API_IDENTIFIER::API_GetSystemFirmwareTable));

	DWORD resultBufferSize = GetSystemFirmwareTable(signature, table, firmwareTable, bufferSize);
	if (resultBufferSize == 0)
	{
		printf("First call failed :(\n");
		free(firmwareTable);
		return NULL;
	}

	// if the buffer was too small, realloc and try again
	if (resultBufferSize > bufferSize)
	{
		PBYTE tmp;

		tmp = static_cast<BYTE*>(realloc(firmwareTable, resultBufferSize));
		if (tmp) {
			firmwareTable = tmp;
			SecureZeroMemory(firmwareTable, resultBufferSize);
			if (GetSystemFirmwareTable(signature, table, firmwareTable, resultBufferSize) == 0)
			{
				printf("Second call failed :(\n");
				free(firmwareTable);
				return NULL;
			}
		}
	}

	*pBufferSize = resultBufferSize;
	return firmwareTable;
}

bool attempt_to_read_memory(void* addr, void* buf, int size)
{
	// this is a dumb trick and I love it
	BOOL b = ReadProcessMemory(GetCurrentProcess(), addr, buf, size, nullptr);
	return b != FALSE;
}

bool attempt_to_read_memory_wow64(PVOID buffer, DWORD size, PVOID64 address)
{
	auto NtWow64ReadVirtualMemory64 = static_cast<pNtWow64ReadVirtualMemory64>(API::GetAPI(API_IDENTIFIER::API_NtWow64ReadVirtualMemory64));
	ULONGLONG bytesRead = 0;

	//printf("dbg: read %llx\n", reinterpret_cast<uint64_t>(address));

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());

	if (hProcess != NULL)
	{
		NTSTATUS status = NtWow64ReadVirtualMemory64(hProcess, address, buffer, size, &bytesRead);
		/*if (status != 0)
		printf("NTSTATUS: %x\n", status);*/

		CloseHandle(hProcess);

		return status == 0;
	}

	printf("attempt_to_read_memory_wow64: Couldn't open process: %u\n", GetLastError());
	return false;
}

bool attempt_to_read_memory_wow64(PVOID buffer, DWORD size, ULONGLONG address)
{
	return attempt_to_read_memory_wow64(buffer, size, reinterpret_cast<PVOID64>(address));
}

std::vector<PMEMORY_BASIC_INFORMATION>* enumerate_memory()
{
	auto regions = new std::vector<PMEMORY_BASIC_INFORMATION>();

#ifdef ENV32BIT
	const PBYTE MaxAddress = (PBYTE)0x7FFFFFFF;
#else
	const PBYTE MaxAddress = (PBYTE)0x7FFFFFFFFFFFFFFFULL;
#endif

	PBYTE addr = 0;
	while (addr < MaxAddress)
	{
		auto mbi = new MEMORY_BASIC_INFORMATION();
		if (VirtualQuery(addr, mbi, sizeof(MEMORY_BASIC_INFORMATION)) <= 0)
			break;
		
		regions->push_back(mbi);

		addr += mbi->RegionSize;
	}

	return regions;
}

std::vector<PMEMORY_BASIC_INFORMATION64>* enumerate_memory_wow64()
{
	if (IsWoW64() == FALSE)
	{
		printf("Not WoW64.\n");
		return nullptr;
	}

	if (!API::IsAvailable(API_NtWow64QueryVirtualMemory64))
	{
		printf("API unavailable.\n");
		return nullptr;
	}

	auto NtWow64QueryVirtualMemory64 = static_cast<pNtWow64QueryVirtualMemory64>(API::GetAPI(API_IDENTIFIER::API_NtWow64QueryVirtualMemory64));

	auto regions = new std::vector<PMEMORY_BASIC_INFORMATION64>();

	const INT64 MaxAddress = 0x7FFFFFFFFFFFFFFFULL;

	INT64 addr = 0;
	while (addr < MaxAddress)
	{
		auto mbi = new MEMORY_BASIC_INFORMATION64();
		ULONG64 returnLength;
		NTSTATUS status;
		if ((status = NtWow64QueryVirtualMemory64(GetCurrentProcess(), (PVOID64)addr, 0, mbi, sizeof(MEMORY_BASIC_INFORMATION64), &returnLength)) != 0)
		{
			printf("Failed at %llx with status %d.\n", addr, status);
			break;
		}

		regions->push_back(mbi);

		addr += mbi->RegionSize;
	}

	return regions;
}
