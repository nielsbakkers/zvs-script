# Zeek Vulnerability Scanner ![Release](https://badgen.net/github/release/nielsbakkers/zvs-script) ![Contributors](https://badgen.net/github/contributors/nielsbakkers/zvs-script)

> This is a vulnerability scanner using Zeek logs and Nmap.

## Casus

For a school project we worked as a group on the following casus: How can a large company (> 50.000 devices) effectively and automatically scan its own network for vulnerabilities regularly without blindly scanning all IPv4 ranges in use or when IPv6 is used.

"What is the best method to scan a 50,000-client network for vulnerabilities without scanning all clients?"

* What is an effective way to find all clients in the network?
* How do you distinguish servers from workstations in the network?
* How can you scan a large number of clients for vulnerabilities?
* How does this process work with clients using IPv6?

## Applications

This project uses several external applications:
 * [Zeek 4.2.2](https://zeek.org/get-zeek/)
 * [Nmap 7.9.2](https://nmap.org/download#linux-rpm)

## Installation

In order to use the script to scan for possible vulnerabilities you need to execute several commands.

### 1. Download the script

Execute the command below to download the script from Github.

``` bash
wget https://raw.githubusercontent.com/nielsbakkers/zvs-script/main/scan_v8.sh
```

## 2. Install Zeek and Nmap

To ensure that the script works as expected make sure that Zeek and Nmap are installed and configured as required.

Nmap install guide
https://nmap.org/download.html

Zeek install guide
https://docs.zeek.org/en/lts/get-started.html

## 3. Run the script

Run the commands below to execute the script.
``` bash
chmod +x scan_v8.sh
./scan_v8.sh
```

## Result

https://user-images.githubusercontent.com/72097417/172565691-28dfb63d-0dfd-4cc3-9c76-726b1e1a55ae.mp4

## Contact

Created by [@nbakkers](https://nbakkers.nl) - Feel free to contact me!
