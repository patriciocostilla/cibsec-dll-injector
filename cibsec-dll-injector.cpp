#include <stdio.h>
#include <windows.h>
#include <iostream>

/*
    Nota: Si el proceso objetivo es x64, la DLL y el proceso inyector también deben estar preparadas para esta plataforma
*/

int main() {
    // Obtenemos el PATH a la DLL a inyectar
    char dllPath[255];
    printf("Path de la dll a inyectar: ");
    scanf_s("%s", dllPath, sizeof(dllPath));
    
    // Obtenemos el handle al proceso objetivo
    int processId;
    printf("Id del proceso objetivo: ");
    scanf_s("%d", &processId);
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (hProcess == NULL || hProcess == INVALID_HANDLE_VALUE) {
        printf("No se pudo abrir el proceso objetivo\n");
        return -1;
    }

    // Asignamos memoria en el proceso objetivo
    PVOID remoteMemory = VirtualAllocEx(hProcess, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    printf("Remote memory: %p\n", remoteMemory);

    // Escribimos el nombre de la dll que queremos que el proceso objetivo cargue
    SIZE_T bytesWritten = 0;
    WriteProcessMemory(hProcess, remoteMemory, dllPath, sizeof(dllPath), &bytesWritten);
    if (bytesWritten == 0) {
        printf("\nNo se pudo inyectar el path de la DLL en el proceso objetivo\n");
        return -1;
    }

    // Creamos un thread que invoca loadlibrary en el proceso destino
    DWORD thread_id = 0;
    HANDLE myHandle = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibraryA, remoteMemory, 0, &thread_id);
    if (myHandle == 0) {
        DWORD err = GetLastError();
        printf("\nNo se pudo crear el hilo de ejecucion en el proceso objetivo\n");
        return -1;
    }

	return 1;
}