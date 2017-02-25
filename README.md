# httpflow

![](https://github.com/six-ddc/httpflow/blob/master/demo.gif?raw=true)

## Installation

*. Install [zlib](http://www.zlib.net/), [libpcap](http://www.tcpdump.org/)

```bash
> curl -sL http://www.zlib.net/zlib-1.2.11.tar.gz -O
> curl -sL http://www.tcpdump.org/release/libpcap-1.8.1.tar.gz -O
> tar zxvf libpcap-1.8.1.tar.gza
> tar zxvf zlib-1.2.11.tar.gz
> cd libpcap-1.8.1 && ./configure && make && make install && cd ..
> cd zlib-1.2.11 && ./configure && make && make install && cd ..
```

*. build httpflow

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

Usage: http_dump [-i interface] [-f filter] [-s snapshot-length] [-w output-path]
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



