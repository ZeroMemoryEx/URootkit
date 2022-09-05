# URootkit

* The user-mode rootkit replaces executables and system libraries and modifies the behavior of application programming interfaces, It alters the security subsystem and displays false information . It can intercept system calls and filter output in order to hide processes, files, system drivers, network ports, registry keys and paths, and system services

* the purpose of this project is to hide a process by intercepting listing tools system calls and manipulate in its structure .

# DETAILS

* NtQuerySystemInformation API Retrieves the specified system information , it has too many flag each flag represent a structure to be retrieved but we are interersted in ```SystemProcessInformation``` this flag Returns an array of SYSTEM_PROCESS_INFORMATION structures, one for each process running in the system These structures contain information about the resource usage of each process, including the number of threads and handles used by the process, the peak page-file usage, and the number of memory pages that the process has allocated.

  ![image](https://user-images.githubusercontent.com/60795188/188508937-73d913e6-5841-4079-a8c5-6b864361653a.png)

*  it takes 4 parameters ``SystemInformationClass`` , ```SystemInformation```, ``SystemInformationLength``, ``ReturnLength`` and returns ```NTSTATUS``` , first we patch NtQuerySystemInformation so whenever NtQuerySystemInformation get called it will get redirected into our function after that we overwrite the address with the original opcodes so we can Retrieve the data structure .


    ![image](https://user-images.githubusercontent.com/60795188/188509688-3795c8d2-a642-4a90-ab08-992f45a05d5f.png)

* we go through every item using by by summing the previous item value and the NextEntryOffset member , when we found our chosen process we sum the current NextEntryOffset with the next one so whenever the listing tool reach the previous item its will jump over the next one meaning the process will be invisibe . 

  ![image](https://user-images.githubusercontent.com/60795188/188508192-7bc6f35a-ed09-4c6e-b570-f4c06f47dd38.png)
  
# lastly

* although this technique can be detected easily using a program i made while ago [Hooks_Hunter](https://github.com/ZeroMemoryEx/Hooks_Hunter) and it can be bypassed using any kernel-mode rootkit  .
