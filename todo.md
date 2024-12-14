MALDEV

- BASIS
	- tips and tricks
	- obfuscation
	- compilacion
	- Binary entropy
	- Binary signature
	- Encrypting strings
	- Payload Storage

- Object enumeration
	- Processes
	- Threads
	- Modules
	- Handles
	- Tokens

- CODE INJECTION
	- Basics
		- VirtualAlloc
		- Remote Process
		- Threat context
		- SEctions and view
		- No CreateThread (direct function pointer, enumthreadwindows, enumchildwindows)
	- Early Bird
	- ApiRecall
	- sRDI
	- Hooking
	- Dll Injection
	- Dll Hijacking
	- Dll Hollowing / Module Stomping
	- COFF Loader
	- AppInit

- Low Priv - EVASION
	- Call Obfuscation
	- Process Hiding
		- Gargoyle
		- Ekko
		- NinjaSploit
		- MapBlinker
	- PPID Spoofing
	- Prevent 3rd Party dll to be loaded
	- Unhooking - Halo's Gate
	- Unhooking - Fresh copy
	- Unhooking - Perun-s Fart
	- cmdline arguments spoofing
	- Silencing ETW
	- Sandbox Evasion

- High Priv - EVASION
	- Blinding EventLog
	- Blocking EDR/AV Communications
		- Firewall rules
		- Routing table
	- Disabling Sysmon



- AntiForsensic
	- Timestomping
	- Hiding Data - ADS
	- Hiding Data - Registry Hives
	- Hiding Data - Extended Atributes
