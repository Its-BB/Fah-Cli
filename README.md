# FahScan

A standalone terminal-only defensive vulnerability scanner.

## Safety rules

FahScan only performs TCP connect scans and passive metadata checks. It does not implement SYN scans, exploit code, brute force, credential attacks, stealth behavior, firewall bypass, malware analysis, CIDR scanning, or mass internet scanning.

# NOTE: Every scan requires `--i-am-authorized`.

## Install

Build from source:

```sh
go build ./cmd/fahscan
```

## First run

```sh
fahscan init
fahscan config list
```

Configuration is stored at `~/.fahscan/config.yaml`. The SQLite database is stored at `~/.fahscan/fahscan.db`.

## Config

Default fields:

```yaml
default_profile: quick
max_concurrency: 25
connect_timeout_ms: 2000
banner_timeout_ms: 1500
http_timeout_ms: 3000
tls_timeout_ms: 3000
max_custom_ports: 100
allow_localhost: true
allow_private_ip: true
output_format: table
theme: monochrome
save_raw_evidence: true
```

Examples:

```sh
fahscan config get default_profile
fahscan config set max_concurrency 10
fahscan config reset
```

## Scan examples

```sh
fahscan scan run localhost --profile quick --i-am-authorized
fahscan scan run 127.0.0.1 --ports 80,443,8080 --i-am-authorized
fahscan scan list
fahscan scan show 1
```

Profiles:

```sh
fahscan ports list
fahscan ports profile quick
fahscan ports profile web
fahscan ports profile database
fahscan ports profile full-safe
```

## Report examples

```sh
fahscan report view 1
fahscan report export 1 --format json --out report.json
fahscan report export 1 --format html --out report.html
fahscan report export 1 --format markdown --out report.md
fahscan report export 1 --format txt --out report.txt
```
Commands:

```sh
fahscan cve import cves.json
fahscan cve list
fahscan cve search apache
fahscan cve stats
```

## Database

```sh
fahscan db stats
fahscan db vacuum
fahscan db backup --out backup.db
fahscan db restore backup.db