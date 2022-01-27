HTTP-Turtle is a tool to discover HTTP services on unusual ports.

## Quick Start

### Python
- `echo example.com > hosts_up.list`
- `python3 gehttp.py -i hosts_up.list -o hosts_http.list -p0-10000 --threads 10`

**Outputfile**
```
example.com:80
example.com:10
```

### Nmap Scripting Engine (NSE)
`nmap --script http-ports.nse -p0-10000 example.com`

**stdout**
```
Nmap scan report for example.com (93.184.216.34)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
| http-ports:
|_  http_port: 93.184.216.34:80
9929/tcp open  nping-echo
```

### Usage Examples

- `./gehttp.py -i hosts --targets --threads 10 --exec 'wfuzz -w directories.txt http://$target/FUZZ'`  
- Scans all ports (0-65535) for HTTP services and fuzzes each result with wfuzz for directories in `directories.txt`  

- `./gehttp.py -i hosts --stdout --delay 10000`  
- Scan all ports with a delay of 10 seconds and print to stdout  

- `nmap --script http-ports.nse example.com | grep http_ports | grep -Eo [0-9].* > results`  
- Use the NSE script to determine HTTP services, extract ip and port  

## Installation

Python3 is required.  

`git clone git+github.com:timonvogel/http-turtle`


## Usage

*Input file format*
```
ip-address
ip-address
ip-address
[...]
```
*... with --target*
```
ip-address:port
ip-address:port
ip-address:port
[...]
```
`ip-address` can be a domain name as well.

*Output file format*
```
ip-address:port
ip-address:port
ip-address:port
[...]
```
*Specifying ports*  
Ports can be specified by ranges 0-9, lists 1,2,3 or a combination 1-4,10-15,8.  

*Threading*  
The number supplied via `--thread` will be multiplied with the number of available cores. For example if there are 6 cores available and `gehttp.py` is called with `--threads 4` 4\*6=24 threads will be run. If `--threads` is 0.5 0.5\*6=3 threads will be run.  
Threads will be automatically killed on SIGINT (CTRL+C) but it can take a moment.  

*--save-page dir, --save-response-dir, --exec*  
These options add an action when a result is found.  
- `--save-page-dir dir` saves all pages (HTML usually) as ip-address:port.html in dir
- `--save-response-dir dir` save the full responses including HTTP headers in dir
- `--exec command` run command on each result, the result parameters (ip-address, port and more) are available as variables (see the help page)

*Output*  
By default a process status is printed to stderr. Nothing is printed to stdout.  
The following options exists:  
```
--stdout:
STDOUT: results
STDERR: log messages

-o
STDOUT: nothing
STDERR: log messages
```
Combination of `--stdout` and `-o` is possible.  

A friendly reminder:  
- stderr can be redirected with `2>`
- stdout can be redirected with `1>` or `>`

## Why this tool?

Admin panels are a wanted resource. Many tool such as [wfuzz](https://github.com/xmendez/wfuzz), [monsoon](https://github.com/RedTeamPentesting/monsoon), [dirbuster](https://sourceforge.net/projects/dirbuster/) exist to fuzz websites to discover admin panels. But there is no plug-and-play tool to discover admin panels on different ports. Though mostly they are discovered anyway I think iterating over a list of IPs with `curl something && echo $ip >> myresults` can be improved. The multithreaded approach of this tool allows for fast scanning and usually completes faster than the nmap version.

Please use this tool in a responsible manner. Thank you.  
