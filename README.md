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

libpcap version 1.3.0
httpflow 0.0.1

Usage: httpflow [-i interface] [-f filter] [-r pcap-file] [-w output-path] [-x pipe-line] [-s snapshot-length]
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
