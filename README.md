# Gopac
A tool to generate pac from gfwlist implements with go

## Installation

Make sure you have a working Go environment.  Go version 1.8+ is supported.  [See
the install instructions for Go](https://golang.org/doc/install.html).

To install cli, simply run:
```bash
$ go get -u github.com/hahasong/gopac

# build
$ cd $GOPATH/src/github.com/hahasong/gopac
$ go build
```

## Usage

```
-f, --file string       path to output pac (default "proxy.pac")
-i, --input string      path to gfwlist
    --precise           use adblock plus algorithm instead of O(1)
                        lookup
-p, --proxy string      the proxy parameter in the pac file, 
                        for example, "SOCKS5 127.0.0.1:1080;" (default "SOCKS5 127.0.0.1:1080; SOCKS 127.0.0.1:1080; DIRECT")
    --user-rule string  user rule file, which will be appended to
                        gfwlist
```

## Example

```bash
$ ./gopac  # run in fast mode use default parameters
$ ./gopac -f proxy_abp.pac  # run in precise mode and output file 'proxy_abp.pac'
$ ./gopac --user-rule user-rule.txt  # merge user-rule.txt content to gfwlist
```
