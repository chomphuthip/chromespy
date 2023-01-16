# chromespy
A malicious DLL that intercepts POST requests in Chromium browsers.

Hastily written in early 2022, chromespy is a malicious DLL that, on attachment to a Chromium process, will replace the instructions responsible for sending a POST request with a ```JMP``` instruction to chromespy code. The pointer in the ```R13``` register is placed into a global variable and a ```getPointersAndLog()``` is called. This function uses the supplied pointer to determine the location of the POST body request and prints it to a console.

This program uses the [Polyhook 2](https://github.com/stevemk14ebr/PolyHook_2_0) library and its [Zydis](https://github.com/zyantific/zydis) dissassembler to handle hooking. This project has not seen any updates and has been sitting on my hard drive for just under a year. It would be better to rewrite it from the ground up rather than try to use it now.

Possible improvements:
1. Make code more legible.
2. Improve portability. The current implementation uses a static offset of the instructions in order to locate them. Different Chromium-derived browsers have the same instructions at different offsets AND use different registers to hold the pointer to the request.
3. Statically compile with dependant libraries. The current implementation requires mulitple DLLs to be loaded in a specific manner (in order to avoid unresolvable references).
