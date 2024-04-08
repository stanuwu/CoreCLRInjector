#define QWORD int64_t
#include <iostream>
#include <windows.h>
#include <WinUser.h>
#include <thread>
#include <sstream>
FILE* f;

HMODULE Dll;

// CORE CLR
bool run()
{
    // CORE CLR CODE WILL GO HERE
    return 0;
}
//

DWORD __stdcall EjectThread(LPVOID lpParameter) {
    Sleep(100);
    FreeLibraryAndExitThread(Dll, 0);
    return 0;
}

bool shutdown(FILE* fp, std::string reason) {
    
    std::cout << reason << std::endl;
    Sleep(1000);
    if (fp != nullptr)
        fclose(fp);
    FreeConsole();
    CreateThread(0, 0, EjectThread, 0, 0, 0);
    return 0;
}

QWORD WINAPI MainThread(LPVOID param)
{
    AllocConsole();
    FILE* fp;
    freopen_s(&fp, "CONOUT$", "w", stdout);
    SetConsoleTitleW(L"CoreCLR Injector");

    std::cout << "Injected..." << std::endl;
    std::cout << "CoreCLR Starting" << std::endl;

    if (run() == 1)
    {
        shutdown(fp, "CoreCLR Error");
    }

    std::cout << "CoreCLR Exited (Insert to Close)" << std::endl;
    while (true)
    {
        Sleep(50);
        if (GetAsyncKeyState(VK_INSERT) & 1) {
            break;
        }
    }

    shutdown(fp, "Shutting Down");
    return 0;
}

BOOL __stdcall DllMain(HINSTANCE hModule, DWORD dwReason, LPVOID lpReserved)
{
    switch (dwReason)
    {
    case 1:
        Dll = hModule;
        HANDLE hMainThread = CreateThread(nullptr, 0, LPTHREAD_START_ROUTINE(MainThread), hModule, 0, nullptr);

        if (hMainThread)
            CloseHandle(hMainThread);

        break;
    }
    return TRUE;
}