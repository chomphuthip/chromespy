#include <stdlib.h>

#include <polyhook2/ZydisDisassembler.hpp>
#include <polyhook2/Detour/x64Detour.hpp>

#include <string>
#include <iostream>
#include <codecvt>
#include <locale>

//DLL Injector stuff
#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>

//bytes we want to overwrite
//chrome.dll + B175E5 - 48 89 C1 - mov rcx,rax
//chrome.dll + B175E8 - 4C 89 EA - mov rdx, r13

//after hook is installed
//chrome.dll + B175E5 - E9 XX XX XX XX - jmp addrOf64BitJmpToOurCode
//chrome.dll + B175EA - NOP

//hook -> 64bit jmp to &setAddrOfReq -> our code (load rax to global QWORD and get pointers for all strings) ->
//  trampoline(execute overwritten bytes and jmp back to chrome.dll + B175EB)

extern "C" void analyze(); //preserve all flags while PointersAndLog is called
extern "C" uint64_t printHEYWithoutStomping();

extern "C" uint64_t addrOfReq = 0;
extern "C" uint64_t hookTramp = NULL;


extern "C" void getPointersAndLog();


NOINLINE void getPointersAndLog() {
    wchar_t* authority = (wchar_t*)(addrOfReq + 192);
    wchar_t* referrer = (wchar_t*)((char*)(authority + authority[-2]) + 24); //authority[-4] is where the length of authority is stored
    //get end of authority, cast to char * so we can move by single bytes, move forward 25 bytes, then recast to wide char pointer

    char* body = ((char*)(referrer + referrer[-2]) + 0xe4);

    if (!iswalnum(authority[0]) || !iswalnum(referrer[0]) || !isalnum(body[0])) {
        return;
    }

    
    std::cout << "Body: " << body << std::endl;
}

extern "C" NOINLINE void printHEY() {
    std::cout << "HEY" << std::endl; // HEY is at chromeHooking.dll+2367C 
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        AllocConsole();
        FILE* f; // there should be a better way to do this
        freopen_s(&f, "CONOUT$", "w", stdout); //CONOUT means console out
        SetConsoleTitle(L"Chrome POST request hook");

        std::cout << "Getting chrome.dll base address..." << std::endl;
        uint64_t chromeDllBaseAddr = (uint64_t)GetModuleHandle(L"chrome.dll");
        std::cout << "chrome.dll base address: " << std::hex << chromeDllBaseAddr << std::endl;

        uint64_t instructionAddress = chromeDllBaseAddr + 0xB175EB;


        PLH::ZydisDisassembler dis(PLH::Mode::x64);
        PLH::x64Detour* detour = new PLH::x64Detour(instructionAddress, (uint64_t)&analyze, &hookTramp, dis);
        if (detour->hook()) {
            std::cout << "HOOKED!!!" << std::endl;
        }

    }
    return TRUE;
}

