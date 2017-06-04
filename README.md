# httpflow

[![Build Status](https://travis-ci.org/six-ddc/httpflow.svg?branch=master)](https://travis-ci.org/six-ddc/httpflow)

![](https://github.com/six-ddc/httpflow/blob/master/demo.gif?raw=true)

## Installation

### MacOs

```bash
brew update
brew install httpflow
```

### Linux

* Install [zlib](http://www.zlib.net/), [libpcap](http://www.tcpdump.org/)

```bash
## On CentOS
yum update
yum install libpcap-devel zlib-devel

## On Ubuntu / Debian
apt-get update
apt-get install libpcap-dev zlib1g-dev
```

* Building httpflow

```bash
> git clone https://github.com/six-ddc/httpflow
> cd httpflow &&  make && make install
```

or directly download [Release](https://github.com/six-ddc/httpflow/releases) binary file.

## Usage

```bash
> httpflow -h
libpcap version libpcap version 1.8.1 -- Apple version 67.60.1
httpflow version 0.0.4

Usage: httpflow [-i interface | -r pcap-file] [-f filter] [-w output-path]

  -i interface    Listen on interface
  -r pcap-file    Read packets from file (which was created by tcpdump with the -w option)
                  Standard input is used if file is '-'
  -f filter       Selects which packets will be dumped
                  If filter expression is given, only packets for which expression is 'true' will be dumped
                  For the expression syntax, see pcap-filter(7)
  -w output-path  Write the http request and response to a specific directory

  For more information, see https://github.com/six-ddc/httpflow

```

* Capture default interface

```bash
> httpflow
```

* Capture all interfaces

```bash
> httpflow -i any
```

* Use the expression to filter the capture results

```bash
# If no expression is given, all packets on the net will be dumped.
# For the expression syntax, see pcap-filter(7).
> httpflow -f 'tcp port 80 and host baidu.com'
```

* Read packets from file

```bash
# tcpdump -w a.cap
> httpflow -r a.cap
```

* Read packets from input

```bash
> tcpdump -w - | httpflow -r -
```
