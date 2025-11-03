## cvemapping

This repo Gathers all available cve exploits from github.

## Installation
```
go install github.com/yadavnikhil17102004/CVE_Map_hehe@latest
```

## Download prebuilt binaries
```
wget https://github.com/yadavnikhil17102004/CVE_Map_hehe/releases/download/v0.0.1/cvemapping-linux-amd64-0.0.1.tgz
tar -xvzf cvemapping-linux-amd64-0.0.1.tgz
rm -rf cvemapping-linux-amd64-0.0.1.tgz
mv cvemapping ~/go/bin/cvemapping
```
Or download [binary release](https://github.com/yadavnikhil17102004/CVE_Map_hehe/releases) for your platform.

## Compile from source
```
git clone --depth 1 github.com/yadavnikhil17102004/CVE_Map_hehe.git
cd cvemapping; go install
```

## Usage
```yaml
Usage of cvemapping:
  -github-token string
        GitHub Token for authentication
  -page string
        Page number to fetch, or 'all' (default "1")
  -year string
        Year to search for CVEs (e.g., 2024, 2020)
```

## Usage Examples
```yaml
echo '"CVE-2024-"' | cvemapping -github-token "TOKEN" -page all -year 2024
```
