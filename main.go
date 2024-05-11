package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

//TODO: notes here
// - Do we really need to embed things in a tag and a sequence or can we get by with just the tag (we lose a lot to both having a length)
// - Do we really need to distinguish the type of ip since they are both octet string + uint8
// - seems adding uint64 will "pack" so we can likely get skinnier ips

type Cert struct {
	Details   Details
	Signature []byte
}
type Details struct {
	Name      string
	Ip        netip.Prefix
	Subnets   []netip.Prefix
	Groups    []string
	NotBefore time.Time
	NotAfter  time.Time
	PublicKey []byte
	Issuer    string
}

const ipv4 = asn1.Tag(0x00 | 0x20 | 0x80)
const ipv6 = asn1.Tag(0x01 | 0x20 | 0x80)

const tagIp = asn1.Tag(0x00 | 0x20 | 0x80)
const tagSubnets = asn1.Tag(0x01 | 0x20 | 0x80)
const tagGroups = asn1.Tag(0x02 | 0x20 | 0x80)

func main() {
	ip, _ := netip.ParsePrefix("192.168.5.1/22")
	subnet1, _ := netip.ParsePrefix("0.0.0.0/1")
	subnet2, _ := netip.ParsePrefix("128.0.0.0/1")
	subnet3, _ := netip.ParsePrefix("::1/1")
	publicKey, _ := hex.DecodeString("68615a67fdf304812a3bb1662726d766aa5fb8700295f80e34a473e6d26d404e")
	issuer := "7eced9f5e1c0503e52d7811937ad1dd2ec70a07f7bb6c4d321d195a8736ef5e3"
	signature, _ := hex.DecodeString("c3625638efe1f3066703e81b0439b767151850420385ffc172a0846920fd5ea00cdbadf4fc225fcda5c36954960c0532c2870046a6c4523c2a7b41894c59f305")

	c := Cert{
		Details: Details{
			Name:      "nas2",
			Ip:        ip,
			Subnets:   []netip.Prefix{subnet1, subnet2, subnet3},
			Groups:    []string{"default", "syncthing"},
			NotBefore: time.Now().Add(-1 * time.Minute),
			NotAfter:  time.Now().Add(time.Minute),
			PublicKey: publicKey,
			Issuer:    issuer,
		},
		Signature: signature,
	}

	fmt.Printf("%+v\n", c)
	fmt.Println("**************************************************************************************")
	b := marshalCert(c)
	fmt.Println(hex.EncodeToString(b))

	c, err := unmarshalCert(b)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Printf("%+v\n", c)
	}
}

func marshalCert(c Cert) []byte {
	var b cryptobyte.Builder
	// Outermost certificate
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {

		// Add the cert details
		b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			// Add the name
			b.AddASN1(asn1.UTF8String, func(b *cryptobyte.Builder) {
				b.AddBytes([]byte(c.Details.Name))
			})

			// Add an ipv4 address and network suffix
			b.AddASN1(tagIp, func(b *cryptobyte.Builder) {
				marshalPrefix(c.Details.Ip, b)
			})

			// Add subnets
			b.AddASN1(tagSubnets, func(b *cryptobyte.Builder) {
				b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
					for _, prefix := range c.Details.Subnets {
						marshalPrefix(prefix, b)
					}
				})
			})

			// Add groups
			b.AddASN1(tagGroups, func(b *cryptobyte.Builder) {
				b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
					for _, group := range c.Details.Groups {
						b.AddASN1(asn1.UTF8String, func(b *cryptobyte.Builder) {
							b.AddBytes([]byte(group))
						})
					}
				})
			})

			// Add not before
			b.AddASN1Uint64(uint64(c.Details.NotBefore.Unix()))

			// Add not after
			b.AddASN1Uint64(uint64(c.Details.NotAfter.Unix()))

			// Add the public key
			b.AddASN1OctetString(c.Details.PublicKey)

			// Add the issuer
			h, err := hex.DecodeString(c.Details.Issuer)
			if err != nil {
				panic(err)
			}
			b.AddASN1OctetString(h)
		})

		// Add the signature
		b.AddASN1OctetString(c.Signature)
	})

	return b.BytesOrPanic()
}

func marshalPrefix(prefix netip.Prefix, b *cryptobyte.Builder) {
	//NOTE: 4in6 does not downcast to ipv4 here
	if prefix.Addr().Is4() {
		b.AddASN1(ipv4, func(b *cryptobyte.Builder) {
			b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
				// Add the IP
				//TODO: is this dumb?
				b.AddASN1OctetString(prefix.Addr().AsSlice())

				// Add the suffix
				b.AddASN1Uint64(uint64(prefix.Bits()))
			})
		})
	} else {
		b.AddASN1(ipv6, func(b *cryptobyte.Builder) {
			b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
				// Add the IP
				//TODO: is this dumb?
				b.AddASN1OctetString(prefix.Addr().AsSlice())

				// Add the suffix
				b.AddASN1Uint64(uint64(prefix.Bits()))
			})
		})
	}
}

var badFormat = errors.New("bad wire format")

func unmarshalCert(b []byte) (Cert, error) {
	c := Cert{}
	fmt.Println("**************************************************************************************")
	var inner, signature, details cryptobyte.String
	input := cryptobyte.String(b)

	// Open the envelope
	if !input.ReadASN1(&inner, asn1.SEQUENCE) || inner.Empty() {
		return c, badFormat
	}

	// Grab the cert details
	if !inner.ReadASN1(&details, asn1.SEQUENCE) || details.Empty() {
		return c, badFormat
	}

	// Grab the signature
	if !inner.ReadASN1(&signature, asn1.OCTET_STRING) || signature.Empty() {
		return c, badFormat
	}
	//TODO: enforce limits
	c.Signature = signature

	//TODO: verify here

	var name cryptobyte.String
	if !details.ReadASN1(&name, asn1.UTF8String) || name.Empty() {
		return c, badFormat
	}
	//TODO: enforce limits
	c.Details.Name = string(name)

	// Read out the ip address
	var ipString cryptobyte.String
	if !details.ReadASN1(&ipString, tagIp) || ipString.Empty() {
		return c, badFormat
	}

	ip, err := unmarshalPrefix(&ipString)
	if err != nil {
		return c, err
	}
	c.Details.Ip = ip

	// Read out any subnets
	var found bool
	if !details.ReadOptionalASN1(&ipString, &found, tagSubnets) {
		return c, badFormat
	}

	if found {
		// Read out the entire chunk
		if !ipString.ReadASN1(&ipString, asn1.SEQUENCE) || ipString.Empty() {
			return c, badFormat
		}

		for !ipString.Empty() {
			subnet, err := unmarshalPrefix(&ipString)
			if err != nil {
				return c, err
			}
			c.Details.Subnets = append(c.Details.Subnets, subnet)
		}
		//ipString.ReadASN1(&ipString, asn1.SEQUENCE)
		//var subnets cryptobyte.String

	}

	// Read out any groups
	if !details.ReadOptionalASN1(&ipString, &found, tagGroups) {
		return c, badFormat
	}

	if found {
		// Read out the entire chunk
		if !ipString.ReadASN1(&ipString, asn1.SEQUENCE) || ipString.Empty() {
			return c, badFormat
		}

		for !ipString.Empty() {
			var val cryptobyte.String
			ipString.ReadASN1(&val, asn1.OCTET_STRING)
			if err != nil {
				return c, err
			}
			c.Details.Groups = append(c.Details.Groups, string(val))
		}
	}

	// Read not before and not after
	var rint int64
	if !details.ReadASN1Integer(&rint) {
		return c, badFormat
	}
	c.Details.NotBefore = time.Unix(rint, 0)

	if !details.ReadASN1Integer(&rint) {
		return c, badFormat
	}
	c.Details.NotAfter = time.Unix(rint, 0)

	// Read public key
	if !details.ReadASN1(&ipString, asn1.OCTET_STRING) || ipString.Empty() {
		return c, badFormat
	}
	c.Details.PublicKey = ipString

	// Read issuer
	if !details.ReadASN1(&ipString, asn1.OCTET_STRING) || ipString.Empty() {
		return c, badFormat
	}
	c.Details.Issuer = hex.EncodeToString(ipString)

	if !details.Empty() {
		fmt.Println("============================================================================================")
		fmt.Println("We didn't read the whole details thing")
		fmt.Println(details)
		fmt.Println("============================================================================================")
	}

	if !input.Empty() {
		fmt.Println("============================================================================================")
		fmt.Println("We didn't read the whole details thing")
		fmt.Println(input)
		fmt.Println("============================================================================================")
	}

	return c, nil
}

func unmarshalPrefix(s *cryptobyte.String) (netip.Prefix, error) {
	var ipc cryptobyte.String
	var tag asn1.Tag

	if !s.ReadAnyASN1(&ipc, &tag) || ipc.Empty() {
		return netip.Prefix{}, badFormat
	}

	if tag == ipv4 {
		var ips cryptobyte.String
		if !ipc.ReadASN1(&ips, asn1.SEQUENCE) || ips.Empty() {
			return netip.Prefix{}, badFormat
		}

		var ip cryptobyte.String
		if !ips.ReadASN1(&ip, asn1.OCTET_STRING) || ip.Empty() {
			return netip.Prefix{}, badFormat
		}

		var suffix cryptobyte.String
		if !ips.ReadASN1(&suffix, asn1.INTEGER) || suffix.Empty() {
			return netip.Prefix{}, badFormat
		}

		addr, ok := netip.AddrFromSlice(ip[:])
		if !ok {
			return netip.Prefix{}, badFormat
		}

		//TODO: check the suffix for safety
		return netip.PrefixFrom(addr, int(suffix[0])), nil

	} else if tag == ipv6 {
		var ips cryptobyte.String
		if !ipc.ReadASN1(&ips, asn1.SEQUENCE) || ips.Empty() {
			return netip.Prefix{}, badFormat
		}

		var ip cryptobyte.String
		if !ips.ReadASN1(&ip, asn1.OCTET_STRING) || ip.Empty() {
			return netip.Prefix{}, badFormat
		}

		var suffix cryptobyte.String
		if !ips.ReadASN1(&suffix, asn1.INTEGER) || suffix.Empty() {
			return netip.Prefix{}, badFormat
		}

		addr, ok := netip.AddrFromSlice(ip[:])
		if !ok {
			return netip.Prefix{}, badFormat
		}

		//TODO: check the suffix for safety
		return netip.PrefixFrom(addr, int(suffix[0])), nil
	}

	return netip.Prefix{}, badFormat
}
