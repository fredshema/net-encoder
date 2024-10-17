package main

import (
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
)

type IPMetadata struct {
	OrgId  uint32
	HostIp string
	VMId   uint32
}

// EncodeMetadataToIPv6 encodes the IPMetadata struct into an IPv6 address
func EncodeMetadataToIPv6(metadata IPMetadata) (net.IP, error) {
	// Convert OrgId and VMId to big.Int values
	orgId := new(big.Int).SetUint64(uint64(metadata.OrgId))
	vmId := new(big.Int).SetUint64(uint64(metadata.VMId))

	// Parse HostIp and decide its size (IPv4 = 32 bits, IPv6 = 128 bits)
	hostIp := net.ParseIP(metadata.HostIp)
	if hostIp == nil {
		return nil, fmt.Errorf("invalid HostIp")
	}

	// Convert HostIp to 64-bit (use IPv4 or truncate IPv6 for this example)
	var hostIpPart big.Int
	if hostIp4 := hostIp.To4(); hostIp4 != nil {
		// It's an IPv4 address
		hostIpPart.SetUint64(uint64(binary.BigEndian.Uint32(hostIp4)))
	} else {
		// It's an IPv6 address, we'll use the lower 64 bits of the IPv6 address
		hostIpPart.SetBytes(hostIp[8:16])
	}

	// Combine OrgId, VMId, and HostIp part into a big.Int
	encodedIP := big.NewInt(0)
	encodedIP.Or(encodedIP, orgId.Lsh(orgId, 96))
	encodedIP.Or(encodedIP, vmId.Lsh(vmId, 64))
	encodedIP.Or(encodedIP, &hostIpPart)

	// Convert the big.Int to a 16-byte IPv6 address
	ipBytes := encodedIP.Bytes()

	// If ipBytes is less than 16 bytes, pad it
	if len(ipBytes) < 16 {
		padded := make([]byte, 16)
		copy(padded[16-len(ipBytes):], ipBytes)
		return net.IP(padded), nil
	}

	return net.IP(ipBytes), nil
}

// DecodeIPv6ToMetadata decodes the IPv6 address into an IPMetadata struct
func DecodeIPv6ToMetadata(ip net.IP) (IPMetadata, error) {
	if len(ip) != 16 {
		return IPMetadata{}, fmt.Errorf("invalid IPv6 address")
	}

	// Convert the IP address to a big.Int
	encodedIP := new(big.Int).SetBytes(ip)

	// Extract OrgId (first 32 bits), VMId (next 32 bits), and HostIp (last 64 bits)
	orgId := uint32(new(big.Int).Rsh(encodedIP, 96).Uint64())
	vmId := uint32(new(big.Int).Rsh(encodedIP, 64).Uint64())

	// Mask the lower 64 bits to get HostIp
	mask := new(big.Int).SetUint64(0xFFFFFFFFFFFFFFFF)
	hostIpPart := new(big.Int).And(encodedIP, mask).Uint64()

	// Convert the last 64 bits back to an IP (assuming it's IPv4 for simplicity)
	hostIp := fmt.Sprintf("%d.%d.%d.%d", byte(hostIpPart>>24), byte(hostIpPart>>16), byte(hostIpPart>>8), byte(hostIpPart))

	return IPMetadata{
		OrgId:  orgId,
		VMId:   vmId,
		HostIp: hostIp,
	}, nil
}

func main() {
	// Create an example metadata struct
	metadata := IPMetadata{
		OrgId:  123456,
		HostIp: "192.168.1.1", // This example is using IPv4
		VMId:   654321,
	}

	// Encode the metadata to an IPv6 address
	encodedIP, err := EncodeMetadataToIPv6(metadata)
	if err != nil {
		fmt.Println("Error encoding:", err)
		return
	}
	fmt.Println("Encoded IPv6 Address:", encodedIP)

	// Decode the IPv6 address back to the metadata
	decodedMetadata, err := DecodeIPv6ToMetadata(encodedIP)
	if err != nil {
		fmt.Println("Error decoding:", err)
		return
	}
	fmt.Printf("Decoded Metadata: %+v\n", decodedMetadata)
}
