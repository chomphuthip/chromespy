# chromespy
A malicious DLL that intercepts POST requests in Chromium browsers.

chromespy is a malicious DLL that, on attachment to a Chromium process, will replace the instructions responsible for sending a POST request with a ```JMP``` instruction to chromespy code. The pointer in the ```R13``` register is placed into a global variable and a ```getPointersAndLog()``` is called. This function uses the supplied pointer to determine the location of the POST body request and prints it to a console.

This program uses the [Polyhook 2](https://github.com/stevemk14ebr/PolyHook_2_0) library and its [Zydis](https://github.com/zyantific/zydis) dissassembler to handle hooking. This project has not seen any updates and has been sitting on my hard drive for just under a year.
