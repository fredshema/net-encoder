# Net Encoder

This is a simple ipv6 network encoder. It takes a bunch of metadata and encodes them into an ipv6 address.

## Usage

```bash
go run main.go
```

## Example output

```
Encoded IPv6 Address: 2001:0:123456:654321:c0a80101
Decoded Metadata: IPMetadata{OrgId:123456, VMId:654321, HostIp:192.168.1.1}
```