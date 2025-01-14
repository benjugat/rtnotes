MALDEV

- BASIS
	[x] tips and tricks
	[x] compilacion and checks
	[x] obfuscation
	[x] Encrypting 
	[x] Payload Storage
	[x] Binary entropy
	[x] Binary improvment
		- signature
		- details
	
- Object enumeration
	[x] Processes
	[x] Modules
	[x] Handles

- CODE INJECTION
	[x] Basics
		[x] VirtualAlloc
		[x] Remote Process
		[x] Threat context
		[x] No CreateThread (direct function pointer, enumthreadwindows, enumchildwindows)
	[x] Sections and view	
	[x] Dll Injection
	[x] Early Bird (APC Call)
	[ ] sRDI
	[ ] Dll Hijacking
	[ ] Dll Hollowing / Module Stomping
	[ ] Dll SideLoading
	[ ] COFF Loader
	[ ] ApiRekall
	

- Hooking
	- [ ] Detour
	- [ ] AppInit
	- [ ] Modifying IAT 


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

- User Impersonation
	[x] Playing with tokens

