// Based On: https://github.com/dotnet/samples/blob/main/core/hosting/src/NativeHost/nativehost.cpp
#define QWORD int64_t
#include <Windows.h>
#include <WinUser.h>
#include <sstream>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <iostream>

// Files From https://www.nuget.org/packages/Microsoft.NETCore.App.Host.win-x64/
#include <coreclr_delegates.h>
#include <hostfxr.h>
#include <nethost.h>

#define STR(s) L ## s
#define CH(c) L ## c
#define DIR_SEPARATOR L'\\'

#define string_compare wcscmp

using string_t = std::basic_string<char_t>;

namespace
{
    // Globals to hold hostfxr exports
    hostfxr_initialize_for_dotnet_command_line_fn init_for_cmd_line_fptr;
    hostfxr_initialize_for_runtime_config_fn init_for_config_fptr;
    hostfxr_get_runtime_delegate_fn get_delegate_fptr;
    hostfxr_run_app_fn run_app_fptr;
    hostfxr_close_fn close_fptr;

    // Forward declarations
    bool load_hostfxr(const char_t *app);
    load_assembly_and_get_function_pointer_fn get_dotnet_load_assembly(const char_t *assembly);

    int run_net(const string_t& root_path);
}

FILE* f;

HMODULE Dll;

// CORE CLR
bool run()
{
    // Get Execution Directory
    TCHAR buffer[MAX_PATH] = { 0 };
    GetModuleFileName( NULL, buffer, MAX_PATH );
    std::wstring::size_type pos = std::wstring(buffer).find_last_of(L"\\/");
    string_t root_path = std::wstring(buffer).substr(0, pos).append(L"\\");
    
    return run_net(root_path);
}

namespace
{
    int run_net(const string_t& root_path)
    {
        // Load HostFxr and get exported hosting functions
        if (!load_hostfxr(nullptr))
        {
            assert(false && "Failure: load_hostfxr()");
            return EXIT_FAILURE;
        }
        
        // Initialize and start the .NET Core runtime
        const string_t config_path = root_path + STR("DotNetLib.runtimeconfig.json");
        load_assembly_and_get_function_pointer_fn load_assembly_and_get_function_pointer = nullptr;
        load_assembly_and_get_function_pointer = get_dotnet_load_assembly(config_path.c_str());
        
        assert(load_assembly_and_get_function_pointer != nullptr && "Failure: get_dotnet_load_assembly()");
        
        // Get Cancer (Load DLL)
        const string_t dotnetlib_path = root_path + STR("DotNetLib.dll");
        const string_t dotnet_type = STR("DotNetLib.Entry, DotNetLib");
        const string_t dotnet_type_method = STR("Init");

        std::cout << "Loading DLL:" << std::endl;
        std::wcout << dotnetlib_path << std::endl;
        std::wcout << dotnet_type << std::endl;
        std::wcout << dotnet_type_method << std::endl;
        
        // Function pointer to managed delegate
        component_entry_point_fn init = nullptr;
        int rc = load_assembly_and_get_function_pointer(
            dotnetlib_path.c_str(),
            dotnet_type.c_str(),
            dotnet_type_method.c_str(),
            nullptr,
            nullptr,
            (void**)&init);
        
        assert(rc == 0 && init != nullptr && "Failure: load_assembly_and_get_function_pointer()");

        // Run managed code
        struct lib_args
        {
        };
        lib_args args
        {
        };
        
        if (init(&args, sizeof(args)) == 0)
        {
            return EXIT_SUCCESS;
        }
        
        return EXIT_FAILURE;
    }
}

namespace
{
    // Forward declarations
    void *load_library(const char_t *);
    void *get_export(void *, const char *);
    
    void *load_library(const char_t *path)
    {
        HMODULE h = ::LoadLibraryW(path);
        assert(h != nullptr);
        return (void*)h;
    }
    void *get_export(void *h, const char *name)
    {
        void *f = ::GetProcAddress((HMODULE)h, name);
        assert(f != nullptr);
        return f;
    }

    
    // Using the nethost library, discover the location of hostfxr and get exports
    bool load_hostfxr(const char_t *assembly_path)
    {
        get_hostfxr_parameters params { sizeof(get_hostfxr_parameters), assembly_path, nullptr };
        
        // Pre-allocate a large buffer for the path to hostfxr
        char_t buffer[MAX_PATH];
        size_t buffer_size = sizeof(buffer) / sizeof(char_t);

        int rc = get_hostfxr_path(buffer, &buffer_size, &params);
        if (rc != 0)
            return false;
        
        // Load hostfxr and get desired exports
        void *lib = load_library(buffer);
        
        init_for_cmd_line_fptr = (hostfxr_initialize_for_dotnet_command_line_fn)get_export(lib, "hostfxr_initialize_for_dotnet_command_line");
        init_for_config_fptr = (hostfxr_initialize_for_runtime_config_fn)get_export(lib, "hostfxr_initialize_for_runtime_config");
        get_delegate_fptr = (hostfxr_get_runtime_delegate_fn)get_export(lib, "hostfxr_get_runtime_delegate");
        run_app_fptr = (hostfxr_run_app_fn)get_export(lib, "hostfxr_run_app");
        close_fptr = (hostfxr_close_fn)get_export(lib, "hostfxr_close");

        return (init_for_config_fptr && get_delegate_fptr && close_fptr);
    }
    
    // Load and initialize .NET Core and get desired function pointer for scenario
    load_assembly_and_get_function_pointer_fn get_dotnet_load_assembly(const char_t *config_path)
    {
        // Load .NET Core
        void *load_assembly_and_get_function_pointer = nullptr;
        hostfxr_handle cxt = nullptr;
        int rc = init_for_config_fptr(config_path, nullptr, &cxt);
        if (rc != 0 || cxt == nullptr)
        {
            std::cout << "Init failed: " << std::hex << std::showbase << rc << std::endl;
            close_fptr(cxt);
            return nullptr;
        }

        // Get the load assembly function pointer
        rc = get_delegate_fptr(
            cxt,
            hdt_load_assembly_and_get_function_pointer,
            &load_assembly_and_get_function_pointer);
        if (rc != 0 || load_assembly_and_get_function_pointer == nullptr)
            std::cout << "Get delegate failed: " << std::hex << std::showbase << rc << std::endl;

        close_fptr(cxt);
        return (load_assembly_and_get_function_pointer_fn)load_assembly_and_get_function_pointer;
    }
}

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

    try
    {
        if (run() == 1)
        {
            std::cout << "CoreCLR Error (Insert to Close)" << std::endl;
        }
        else
        {
            std::cout << "CoreCLR Exited (Insert to Close)" << std::endl;
        }
    }
    catch (int exception)
    {
        std::cout << "Exception: " << exception << std::endl;
    }
    
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