package main

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

//TODO: notes here
// - We could avoid the out sequence in the ip assignment and save another 2-3 bytes, this means putting the hi/lo/suffix as top level items

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
			NotBefore: time.Unix(1707416815, 0),
			NotAfter:  time.Unix(1743416815, 0),
			PublicKey: publicKey,
			Issuer:    issuer,
		},
		Signature: signature,
	}

	fmt.Printf("%+v\n", c)
	fmt.Println("**************************************************************************************")
	b := marshalCert(c)
	fmt.Println(hex.EncodeToString(b))

	//b, _ := hex.DecodeString("3081dea0819980046e617332a10a810500c0a80501820116a21f3006810100820101300a810500800000008201013009800100810101820101a3140c0764656661756c740c0973796e637468696e67840465c51cef850467ea6def862068615a67fdf304812a3bb1662726d766aa5fb8700295f80e34a473e6d26d404e87207eced9f5e1c0503e52d7811937ad1dd2ec70a07f7bb6c4d321d195a8736ef5e38140c3625638efe1f3066703e81b0439b767151850420385ffc172a0846920fd5ea00cdbadf4fc225fcda5c36954960c0532c2870046a6c4523c2a7b41894c59f305")

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
		b.AddASN1(asn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
			// Add the name
			b.AddASN1(asn1.Tag(0).ContextSpecific(), func(b *cryptobyte.Builder) {
				b.AddBytes([]byte(c.Details.Name))
			})

			// Add an ipv4 address and network suffix
			b.AddASN1(asn1.Tag(1).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
				marshalPrefix(c.Details.Ip, b)
			})

			// Add subnets
			b.AddASN1(asn1.Tag(2).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
				for _, prefix := range c.Details.Subnets {
					b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
						marshalPrefix(prefix, b)
					})
				}
			})

			// Add groups
			b.AddASN1(asn1.Tag(3).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
				for _, group := range c.Details.Groups {
					b.AddASN1(asn1.UTF8String, func(b *cryptobyte.Builder) {
						b.AddBytes([]byte(group))
					})
				}
			})

			// Add not before
			b.AddASN1Int64WithTag(c.Details.NotBefore.Unix(), asn1.Tag(4).ContextSpecific())

			// Add not after
			b.AddASN1Int64WithTag(c.Details.NotAfter.Unix(), asn1.Tag(5).ContextSpecific())

			// Add the public key
			b.AddASN1(asn1.Tag(6).ContextSpecific(), func(b *cryptobyte.Builder) {
				b.AddBytes(c.Details.PublicKey)
			})

			// Add the issuer
			h, err := hex.DecodeString(c.Details.Issuer)
			if err != nil {
				panic(err)
			}
			b.AddASN1(asn1.Tag(7).ContextSpecific(), func(b *cryptobyte.Builder) {
				b.AddBytes(h)
			})
		})

		// Add the signature
		b.AddASN1(asn1.Tag(1).ContextSpecific(), func(b *cryptobyte.Builder) {
			b.AddBytes(c.Signature)
		})
	})

	return b.BytesOrPanic()
}

func marshalPrefix(prefix netip.Prefix, b *cryptobyte.Builder) {
	//NOTE: 4in6 does not downcast to ipv4 here
	if prefix.Addr().Is4() {
		// Add the IP
		ip := prefix.Addr().AsSlice()
		b.AddASN1Int64WithTag(int64(binary.BigEndian.Uint32(ip)), asn1.Tag(1).ContextSpecific())

	} else {
		// Add the IP
		ip := prefix.Addr().As16()
		b.AddASN1Int64WithTag(int64(binary.BigEndian.Uint64(ip[:8])), asn1.Tag(0).ContextSpecific())
		b.AddASN1Int64WithTag(int64(binary.BigEndian.Uint64(ip[8:])), asn1.Tag(1).ContextSpecific())
	}

	// Add the suffix
	b.AddASN1Int64WithTag(int64(prefix.Bits()), asn1.Tag(2).ContextSpecific())
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
	if !inner.ReadASN1(&details, asn1.Tag(0).Constructed().ContextSpecific()) || details.Empty() {
		return c, badFormat
	}

	// Grab the signature
	if !inner.ReadASN1(&signature, asn1.Tag(1).ContextSpecific()) || signature.Empty() {
		return c, badFormat
	}
	//TODO: enforce limits
	c.Signature = signature

	//TODO: verify here

	var name cryptobyte.String
	if !details.ReadASN1(&name, asn1.Tag(0).ContextSpecific()) || name.Empty() {
		return c, badFormat
	}
	//TODO: enforce limits
	c.Details.Name = string(name)

	// Read out the ip address
	var ipString cryptobyte.String
	if !details.ReadASN1(&ipString, asn1.Tag(1).Constructed().ContextSpecific()) || ipString.Empty() {
		return c, badFormat
	}

	ip, err := unmarshalPrefix(&ipString)
	if err != nil {
		return c, err
	}
	c.Details.Ip = ip

	// Read out any subnets
	var found bool
	if !details.ReadOptionalASN1(&ipString, &found, asn1.Tag(2).Constructed().ContextSpecific()) {
		return c, badFormat
	}

	if found {
		// Read out the entire chunk

		for !ipString.Empty() {
			var val cryptobyte.String
			if !ipString.ReadASN1(&val, asn1.SEQUENCE) || val.Empty() {
				return c, badFormat
			}

			subnet, err := unmarshalPrefix(&val)
			if err != nil {
				return c, err
			}
			c.Details.Subnets = append(c.Details.Subnets, subnet)
		}
		//ipString.ReadASN1(&ipString, asn1.SEQUENCE)
		//var subnets cryptobyte.String

	}

	// Read out any groups
	if !details.ReadOptionalASN1(&ipString, &found, asn1.Tag(3).Constructed().ContextSpecific()) {
		return c, badFormat
	}

	if found {
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
	if !details.ReadASN1Int64WithTag(&rint, asn1.Tag(4).ContextSpecific()) {
		return c, badFormat
	}
	c.Details.NotBefore = time.Unix(rint, 0)

	if !details.ReadASN1Int64WithTag(&rint, asn1.Tag(5).ContextSpecific()) {
		return c, badFormat
	}
	c.Details.NotAfter = time.Unix(rint, 0)

	// Read public key
	if !details.ReadASN1(&ipString, asn1.Tag(6).ContextSpecific()) || ipString.Empty() {
		return c, badFormat
	}
	c.Details.PublicKey = ipString

	// Read issuer
	if !details.ReadASN1(&ipString, asn1.Tag(7).ContextSpecific()) || ipString.Empty() {
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
	var hi int64
	hiSet := false
	if s.PeekASN1Tag(asn1.Tag(0).ContextSpecific()) {
		if !s.ReadASN1Int64WithTag(&hi, asn1.Tag(0).ContextSpecific()) {
			return netip.Prefix{}, badFormat
		}
		hiSet = true
	}

	var lo int64
	if !s.ReadASN1Int64WithTag(&lo, asn1.Tag(1).ContextSpecific()) {
		return netip.Prefix{}, badFormat
	}

	var suffix cryptobyte.String
	if !s.ReadASN1(&suffix, asn1.Tag(2).ContextSpecific()) || suffix.Empty() {
		return netip.Prefix{}, badFormat
	}

	ip := make([]byte, 0, 16)
	if !hiSet {
		ip = ip[:4]
		binary.BigEndian.PutUint32(ip, uint32(lo))
	} else {
		ip = ip[:16]
		binary.BigEndian.PutUint64(ip[:8], uint64(hi))
		binary.BigEndian.PutUint64(ip[8:], uint64(lo))
	}

	addr, ok := netip.AddrFromSlice(ip)
	if !ok || !addr.IsValid() {
		return netip.Prefix{}, badFormat
	}

	//TODO: check the suffix for safety
	return netip.PrefixFrom(addr, int(suffix[0])), nil
}
