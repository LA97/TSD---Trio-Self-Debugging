# TSD---Trio-Self-Debugging
new anti-reversing method, based on the self debugging anti reversing method.

the flow is as follow:

1. a parent process, which is also a packer, unpack a child process and debug it.
2. the child process, iterate the system processes and debug the first process it could.
3. the chlild process inject a dll into the debugged process.
4. the dll is loaded, and the dl-main function, makes the process debug the parent process.


in this way, we accomplish, a very special relationship between these process.
we've created a chain of process, that each one debug the next process in the chain.
this way, we got a little command and control work flow between the processes using the debug events.
each unregular event comming from a certain process, make is debugger process, act as follow.


files description :

- dll-injector - this is basically the malware and the unpacked child process.
- mydll - this is the injected dll.
- packer - this is the parent process. 
- host.exe - this is just hello world sample process to infect (it as a while(true) loop to avoid termination).
