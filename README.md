# ASN Mapper Pro

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A fast and comprehensive surface mapper using ASN or domain input for reconnaissance and bug bounty hunting.

## Features

- ASN to IP range mapping
- Mass parallel scanning
- Subdomain enumeration
- Service detection
- SSL certificate inspection
- Customizable scanning parameters

## Installation

```bash
git clone https://github.com/yourusername/ASN-Mapper.git
cd ASN-Mapper
sudo apt install -y $(cat requirements.txt)
```

## Usage

Basic domain scan:
```bash
./asn_mapper.sh -t target.com -o results.txt
```

ASN scan:
```bash
./asn_mapper.sh -A AS12345 -p 80,443,8080 -r 10000
```
