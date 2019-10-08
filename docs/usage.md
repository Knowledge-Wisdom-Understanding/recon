# Usage

To scan a single target and enumerate based off of nmap results:

```shell
python3 recon.py -t 10.10.10.10
```

To Enumerate Web with larger wordlists

- If you don't want to specify a directory , you can just enter ' ' as the argument for --web

```shell
python3 recon.py -t 10.10.10.10 -w secret
python3 recon.py -t 10.10.10.10 -w somedirectory
python3 recon.py -t 10.10.10.10 -w ' '
```

To Scan + Enumerate all IPv4 addr's in ips.txt file

```shell
python3 recon.py -f ips.txt
```

To Fuzz all found php urls for parameters, you can use the -F --FUZZ flag with no argument.
The Fuzzer will automatically grab any cookies from the urls and add those cookies to the command
used by parameth.

```shell
python3 recon.py -t 10.10.10.10 --FUZZ
```

Brute force ssh users on default port 22 If unique valid users found, brute force passwords

```shell
python3 recon.py -t 10.10.10.10 -b ssh
```

Same as above but for ssh on port 2222 etc...

```shell
python3 recon.py -t 10.10.10.10 -b ssh -p 2222
python3 recon.py -t 10.10.10.10 -b ssh -p 2222 -u slickrick
```

To ignore certain services from being scanned you can specify the -i , --ignore flag.  
When specifying multiple services to ignore, services MUST be space delimited.
All the available ignore choices are:

```text
http,httpcms,ssl,sslcms,aquatone,smb,dns,ldap,oracle,source,proxy,proxycms,fulltcp,topports,remaining,searchsploit
```

```shell
python3 recon.py -t 10.10.10.10 -i http
python3 recon.py -t 10.10.10.10 -i http ssl
python3 recon.py --target 10.10.10.10 --ignore fulltcp http
```