# DefinitelyNotSLIN

# Chapter 0

## Hostname

- `hostnamectl set-hostname <hostname>` to change hostname

## User account and group

- `useradd <name>` to add user
- `passwd <name>` to set password for user
- `groupadd <group name>` to create a new group
- `usermod -aG <groupname> <user>` to add user to group
- `chgrp <groupname> <file>` to change group owner of the file
- 







# Chapter 1

## SSH

### Changing default port number for sshd

1. `netstate -tunap | grep sshd` to check which port the service is running on
2. `vi /etc/ssh/sshd_config` and change the port number
3. Need to change the SELinux policy to allow changing of port number `semanage port –a –t ssh_port_t –p tcp <port number>`
4. `systemctl restart sshd`
5. `ssh –p <port number> <ip address>`

### Secure Copy (SCP) and Secure FTP (SFTP)

`scp <serverIP>:<filename> .` The dot at the back is to represent the current directory

`sftp <username>@<ip address>`

### Network Configuration

##### Network Manager’s Command Line

- `nmcli device` or `nmcli d` to view the network devices

- `nmcli d show <device number>` to view more details about the network interface

- `route` will show the current gateway IP

- `cat /etc/resolv.conf` to view the current DNS Server

- `nmcli connection modify <device number> ipv4.addresses  "<Current IP and subnet mask> <current gateway>" ipv4.dns <current DNS Server>` for Centos release == 7.0

- ``nmcli connection modify <device number> ipv4.addresses <Current IP and subnet mask> ipv4.gateway <current gateway>" ipv4.dns <current DNS Server>` for Centos release > 7.0

- `nmcli connection modify eno16777736 ipv4.method manual` to specify using static IP address for network interface

- `nmcli device disconnect <device number>`

- `nmcli device connect <device number>`

- `/etc/sysconfig/network-scripts/ifcfg-<device number> ` to view the network settings you just made

- DNS setting for the network card in `/etc/sysconfig/network-scripts/ifcfg-<device number> ` will override the settings in global `/etc/resolv.conf`

- Changes made using ip or ifconfig will be lost upon next reboot. Permanent change will have to modify config files `/etc/sysconfig/network-scripts/ifcfg-eno1677736` or `/etc/sysconfig/network`

- Bring up and down a network interface

  ```
  nmcli c down eno1677736
  nmcli c up eno16777736
  ```

### Kernel parameters

- `sysctl -a` to view the list of available kernel parameters and their current values
- `sysctl -w net.ipv4.icmp_echo_ignore_all=1` to set kernel parameters to ignore ping packets
- `vi /etc/sysctl.conf` to set the kernel parameter back and also make changes in the kernel parameters persistent across reboots
- `sysctl -p` to load the settings from `/etc/systctl.conf`

### Prevent root login

- as Root, `visudo` and add `student ALL=ALL` to the end of the file. This will allow user student to run the `sudo` command
- Edit `/etc/passwd` to ` root:x:0:0:root:/root:/sbin/nologin` to change to non-interactive shell

### Anonymous access to vsftpd service

- `systemctl is-enabled vsftpd` to check if the service will be automatically started on bootup
- `systemctl enable vsftpd` to set the service to be automatically started on every bootup
- `systemctl start vsftpd` to start the service
- `vi /etc/vsftpd/vsftpd.conf` and edit `anonymous_enable=YES` to allow anonymous access

### Chrooting vsftpd users to their home directories

- ` setsebool -P ftp_home_dir on` to configure SELinux to allow users to access their home directories
- Edit `/etc/vsftpd/vsftpd.conf` and edit `chroot_list_enable=YES`,`chroot_list_file=/etc/vsftpd/chroot_list` and add `allow_writeable_chroot=YES`, `passwd_chroot_enable=YES`
- create the file `/etc/vsftpd/chroot_list` and add in the users to chroot

### xinetd

- `systemctl start xinetd`
- `vi /etc/xinetd.d/<service name>` and edit `disable=no` to enable tftp

### SELinux

- `getenforce` to check which SELinux mode the system is in
- `setenforce 0` to set to Permissive mode
- `setenforce 1` to set to Enforcing mode
- `getsebool -a | less` to view the SELinux booleans
- edit `/etc/selinux/config` to set the SELinux mode upon bootup
- `ls -lZ <directory>` to view SELinux file contexts of the directory
- `chcon -t <reference filename> <file to change> ` to change file context
- `restorecon <filename>` to reset back the correct file context of the file
- `chcon -t public_content_rw_ <filename>`  to change the file context to be publicly writeable
- `setsebool –P ftpd_anon_write on` to set SELinux boolean to allow anonymous FTP write. The `-P` options is to make the modification persist across reboot
- SELinux violations are logged to `/var/log/audit/audit.log`

### SED

- `sed s/<word to change>/<change with>/ /<filename>` to change the first occurrence
- `sed s/<word to change>/<change with>/g /<filename>` to change the all occurrences
- sed only print out the modified content, does not change the file content.
- use `-i` option to apply modification to the file
- need to escape special characters with `\`
- Chpt 1, page 36

### AWK

- `awk -F “\t” ‘$3 ~/A/ {print $1, $2, $3}’ <file> | sort` to print the first 3 columns if the third column contains the letter “A” and sort alphabetically.
- `-F` option is to specify the column separator



# Chpt 2

`chmod g+s` will set the group ID of the directory. All new files and subdirectories created within the current directory inherit the group ID of the directory, rather than the primary group ID of the user who created the file.

## Apache

- `yum install httpd`
- `systemctl start httpd`
- `systemctl disable/enable httpd`

## Apache Configuration

- Main config file is located at `/etc/httpd/conf/httpd.conf`

- manual can be installed using `yum install httpd-manual` and browse to `http://localhost/manual`

- Log files are found at `/var/log/httpd/access_log` and `/var/log/httpd/error_log`

- If the directory does not contain the file specified in DirectoryIndex in the main config file, then a listing of files in the directory will be displayed

- Directory listing can be disabled by  either appending the following to the end of the main config file `/etc/httpd/conf/httpd.conf` or creating a new file `/etc/httpd/httpd.conf/books.conf`

  ```
  <Directory /var/www/html/books>
  
  	Options -Indexes
  
  </Directory>
  ```

- Always remember to reload or restart the htttpd service after changing the config file

- ```
  /etc/httpd/conf/httpd.conf
  Global Section : configuration to the web server (including virtual servers) as a whole
  Main Section : configuration to the main server
  Virtual Servers : configuration for specific virtual server
   /etc/httpd/conf.d/*.conf
  Normally holds virtual server config files
  ```

  ServerRoot specifies the directory where config files are stored

- DocumentRoot specified the directory where web pages are stored

- DirectoryIndex is the default documents to search for is no page is specified in the URL

- Apache Modules (Page 12 of Chpt 2)

- 4 Types of containers (Page 14)

  - Directory
  - Location
  - Files
  - Virtual Hosts

### Access Control

- Specify in the main config file or the individual config file.

  ```
  <Directory /var/www/html/books>
      Options –Indexes
      Require all denied
      Require ip your_client_ip  your_server_ip
  </Directory>
  ```

### SSL

- `yum install mod_ssl`
- Default pair of private key and certificate will be generated `Private key : /etc/pki/tls/private/localhost.key` and `Certificate :  /etc/pki/tls/certs/localhost.crt`
- Configuration file can be found under `/etc/httpd/conf.d/ssl.conf`

### Name Based Virtual Host

- Resolve hostname to IP by adding to `/etc/hosts`

  - `server_ip	www.flowers.com`

- Create a directory `/var/www/flowers

- Create `index.html`

- Create a new file `flowers.conf` under `/etc/httpd/conf.d/`

  ```
  <VirtualHost your_server_ip:80>
      ServerName www.flowers.com
      DocumentRoot /var/www/flowers
      ErrorLog /var/log/httpd/flowers-error_log
      CustomLog /var/log/httpd/flowers-access_log combined
  </VirtualHost>
  
  ```

### CGI SCRIPTS

- Install Python3.6 (page 4)

- `mkdir /var/www/fruits-cgi-bin` to store the CGI scripts

- Set SELinux file context for the directory

  - `chcon -t httpd_sys_script_exec_t  /var/www/fruits-cgi-bin`

- create python script in the directory

  ```
  #!/usr/bin/env python3
  print("Content-type: text/html\n\n")
  print("Hello World")
  ```

- make the file world-executable `chmod +x`

- Add ScriptAlias line to the VirtualHost container for `www.fruits.com`

  ```
  <VirtualHost your_server_ip:80>
      ServerName www.fruits.com
      DocumentRoot /var/www/fruits
      ErrorLog /var/log/httpd/fruits-error_log
      CustomLog /var/log/httpd/fruits-access_log combined
      ScriptAlias /cgi-bin/ /var/www/fruits-cgi-bin/
  </VirtualHost>
  ```

- Browse to `http://www.fruits.com/cgi-bin/hello.py`

### User Authentication (Web site access control)

- Use htpasswd command to create apache users ( the -c option is used when adding first user)

  - `htpasswd -cm /etc/httpd/conf/flowers-users bob`
  - `htpasswd -m /etc/httpd/conf/flowers-users bob`

- Create the file `/var/www/flowers/.htaccess` in the DocumentRoot

  ```
  AuthType basic
  AuthName "Flowers Website"
  AuthUserFile /etc/httpd/conf/flowers-users
  require user bob
  ```

- Edit the `/etc/httpd/conf.d/flowers.conf` and add

  ```
  <Directory /var/www/flowers>
      AllowOverride AuthConfig
  </Directory>
  ```

- Changes make to `.htaccess` do not require the server to be restarted.

## Curl

- `curl -u username:password <website>`

## Squid

- `yum install squid`
- Edit `/etc/squid/squid.conf`
  - Create Access Control List (acl) for own subnet `acl my_net src 192.168.136.0/24`
  - Create the http_access `http_access allow my_net`
  - Set the parameter visible_hostname to our hostname `visible_hostname server.example.com`
- Squid run on port 3128 by default
- Check for error messages `/var/log/messages`
- View Squid access log `tail /var/log/squid/access.log`
- Block website `/etc/squid/squid.conf`
  - `acl bad_sites dstdomain .yahoo.com`
  - `http_access deny bad_sites`

## Tomcat Server

- `yum install tomcat`
- `tomcat version`
- Tomcat web pages are stored in `/var/lib/tomcat/webapps`
- Make root dir `mkdir ROOT`
- Create default page `/var/lib/tomcat/webapps/ROOT/index.jsp`
- Default server config file `/etc/tomcat/server.xml`
- To shutdown the server
  - `telnet 127.0.0.1 8005` and type `SHUTDOWN`
- To deploy a war file, copy the file to `/var/lib/tomcat/webapps`

## Nginx Web Server

- `yum install gcc`
- `yum install pcre pcre-devel`
- `yum install zlib zlib-devel`
- Download latest stable version of nginx from `www.nginx.org`
  - move the file to `/usr/src`
  - Extract the file `tar -xvf nginx-1.7.7.tar.gz`
  - `cd nginx-1.7.7`
  - `./configure`
  - `make`
  - `make install`
- The nginx config file is stored in `/usr/local/nginx/conf/nginx.conf`
- Start nginx using `/usr/local/nginx/sbin/nginx`
- Check nginx is running `netstat -tunap | grep nginx`
- Make the worker process run as user `nginx`
  - `useradd -s /sbin/nologin -d /usr/local/nginx nginx`
  - Edit the config file `user nginx nginx; worker_processes 2;`
  - restart nginx `/usr/local/nginx/sbin/nginx –s stop` and `/usr/local/nginx/sbin/nginx`

### Configuring nginx as a service

- Create a text file `/usr/lib/systemd/system/nginx.service`

  ```
  [Unit]
  Description=The NGINX HTTP server
  After=syslog.target network.target remote-fs.target nss-lookup.target
  
  [Service]
  Type=forking
  PIDFile=/usr/local/nginx/logs/nginx.pid
  ExecStartPre=/usr/local/nginx/sbin/nginx -t
  ExecStart=/usr/local/nginx/sbin/nginx
  ExecReload=/bin/kill -s HUP $MAINPID
  ExecStop=/bin/kill -s QUIT $MAINPID
  PrivateTmp=true
  
  [Install]
  WantedBy=multi-user.target
  
  ```

- Try to start and stop nginx

  ```
  systemctl status nginx
  systemctl stop nginx
  systemctl start nginx
  ```

# Chapter 3 File Systems and Network File Service (NFS)

## Setting up XFS filesystem

- `fdisk -l` to view all known disks
- `fdisk /dev/sda`
- `m` to view available options
- `p` to list existing partitions on the hard disk
- `n` to create new partition
  - `p` to create primary partition
  - `+100M` to create a 100MB partition
  - `p` to list partition info
  - `w` to write changes to disk and exit fdisk

## Format partition with XFS filesystem

- Format XFS filesystem`mkfs -t xfs /dev/sda3` sda3 is the newly created partition

- Create mount point `mkdir /filesys1`

- Find UUID of the new filesystem `blkid /dev/sda3`

- Edit `/etc/fstab` so filesystem will automatically mount on bootup

  ```
  UUID=”a11f1b0-2f5b-49e8-ba43-13de7990d3b9”	/filesys1	xfs defaults 0 0
  ```

- `mount /filesys1`

- `df` to view current storage usage

## Exporting directories on NFS server

- `yum list nfs-utils` to check if nfs packages is installed

- `systemctl status nfs-server` 

- Create a directory and make it world writeable

  - `mkdir -p /exports/data`
  - `chmod 777 /exports/data`

- Edit `/etc/exports/`

  - `/exports/data <clientIP>(ro,sync)`

- `exportfs -r` to re-export all the entries in `/etc/exports`

- `exportfs -v` to check the exports

- NFSd run on TCP port 2049

- rpcbind runs on TCP and UDP port 111, also uses loopback interface

- ```
  The following 2 lines in /etc/exports have different meanings
  /data    192.168.1.0/24(rw)
  /data    192.168.1.0/24 (rw)
  The first config line means /data will be exported to clients in the subnet 192.168.1.0/24 with read-write options
  The second config line means /data will be exported to clients in the subnet 192.168.1.0/24 with default options (read-only) and exported to all other systems with read-write option
  ```

- If userA on server with UID 505 have rwx permission. Then userB with UID 505 on client will also have rwx permission

## Mounting exported directories on NFS Client

- `yum list nfs-utils`
- Create mount point `mkdir -p /mount/data`
- `mount serverIP:/exports/data /mount/data -o rw`
- unmount using `umount /mount/data`
- Files created by root over the NFS share are owned by nfsnobody. Directories are exported with the root_squash option, which will map user root to user nfsnobody when accessing the exported directory
- Mount on bootup using `/etc/fstab`
  - `serverIP:/exports/data      /mount/data    nfs   defaults  0 0`
  - `mount /mount/data`
- The root of all exported file systems on the NFS server is known as the pseudo-root
- If the client mounts the pseudo-root, all exported file systems are mounted on the client

# Network and Service Access Controls (Firewalld and TCP wrappers)

## Zones and predefined services of firewalld

- Firewalld GUI

- `firewall-config`

- `firewall-cmd --get-zones`

- `firewall-cmd --list-all-zones`

- `firewall-cmd --get-default-zone`

- `firewall-cmd –list-services`

- `firewall-cmd --reload`

- Permanent configuration will be saved to a file `/etc/firewalld/zones/public.xml` and applied the next time the firewall is started

- Remove service in permanent `firewall-cmd --permanent --zone=public --remove-service=telnet`

- Predefined configurations of each zone are specified in `/usr/lib/firewalld/zones`. NOTE: Do not modified them

- User-modified zone configuration are stored in `/etc/firewalld/zones`

- Predefined services are specified in `/usr/lib/firewalld/services`

- User-created or modified services will be listed in `/etc/firewalld/services`

- Adding port using command line

  ```
  firewall-cmd –-zone=public –-add-port=8080/tcp
  firewall-cmd --permanent --zone=public       ---add-port=8091-8095/tcp
  ```

- `man firewalld.zone / firewalld.service / firewalld.icmptype`

## Rich Rules

- Rules are stored in zone config files `/etc/firewalld/zones`
- First rule that matches the packet will be applied
- Parsing of rules
  1. Log rules
  2. Drop rules
  3. Accept rules
- Only you to specify destination, source, ports and actions, loggings and etc.
- `firewall-cmd --permanent --zone=public –add-rich-rule='rule family=ipv4 service name=ftp source address=192.168.136.0/24 accept'`
- Logged packet are found at `/var/log/messages`
- `man firewalld.richlanguage`

## Network Address Translation (NAT)

- Enable IP Masquerade zone which means all outgoing packet will be modified to have the same source IP as the client network interface card
- On the Port forwarding port, forward all incoming packets going to Port 80 on the client to Port 80 on the server.
- Verify that the source address changed by `cat /var/log/httpd/access_log` on the server

## Using direct interface (page 18 of chpt 4)

- To create rules to control the outgoing traffic.

- Rules with priority 1 will be matched first.

- List all current rules for direct interface `firewall-cmd --direct --get-all-rules`

- To block all outgoing traffic `firewall-cmd --direct --add-rule ipv4 filter OUTPUT 99 -j DROP`

- Allow outgoing traffic `firewall-cmd --direct --add-rule ipv4 filter OUTPUT 2 -p tcp --dport 80 -j ACCEPT` and`firewall-cmd --direct --add-rule ipv4 filter OUTPUT 3 -p udp    --dport 53 -j ACCEPT`

- Allow outgoing packets that belong to a connection that is already established `firewall-cmd --direct --add-rule ipv4 filter OUTPUT 1 -m state --state ESTABLISHED,RELATED -j ACCEPT`

- `firwall-cmd --direct --get-all-rules` will list all rules through direct interface, while `firewall-cmd -list-all` will not list

- To make the rules permanent, need the `--permanent` option.

- Permanent direct interface rules are stored in `/etc/firewalld/direct.xml`

- To remove direct interface rules

  - ```
    firewall-cmd --direct --remove-rule ipv4 filter OUTPUT 1       –m state --state ESTABLISHED,RELATED -j ACCEPT
    firewall-cmd --direct --remove-rule ipv4 filter OUTPUT 2 -p tcp    --dport 80 -j ACCEPT
    firewall-cmd --direct --remove-rule ipv4 filter OUTPUT 3 -p udp    --dport 53 -j ACCEPT
    firewall-cmd --direct --remove-rule ipv4 filter OUTPUT 99      -j DROP
    ```

  - Using Firewall GUI

## TCP Wrappers

- Many network services are linked to libwrap.so library. Access to these network services can be controlled by `/etc/hosts.allow` and `/etc/hosts.deny`

- Find the full path to the vsftpd program `which vsftfpd`

- Run `ldd /usr/sbin/vsftpd | grep ‘libwrap.so’`. If libwrap.so is among the list of libraries, then the service can be controlled using `/etc/hosts.deny` and `/etc/hosts.allow`

- `ldd` may not detect the libwrap.so library. Need to use `strings usr/sbin/vsftpd | grep hosts`_access

- ```
  sshd: clientIP
  vsftpd: ALL EXCEPT clientIP
  ALL : ALL
  ```

  Rules in `/etc/hosts.allow` are applied first

- If no match in either `/etc/hosts.allow` or `/etc/hosts.deny`, then allow connection
