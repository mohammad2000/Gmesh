// Package stunlite is the slice of STUN (RFC 5389) the mesh needs: a
// binding request, and a success response carrying XOR-MAPPED-ADDRESS. The
// relay answers these on its UDP port so a node can learn how its
// WireGuard port looks from outside its NAT.
package stunlite

import (
	"crypto/rand"
	"encoding/binary"
	"net/netip"
)

const (
	cookie         = 0x2112A442
	bindingRequest = 0x0001
	bindingSuccess = 0x0101
	attrXORMapped  = 0x0020
	headerLen      = 20
	familyIPv4     = 0x01
	familyIPv6     = 0x02
)

// TxID is a STUN transaction ID.
type TxID [12]byte

// NewTxID returns a random transaction ID.
func NewTxID() TxID {
	var t TxID
	_, _ = rand.Read(t[:])
	return t
}

func isSTUN(b []byte) bool {
	return len(b) >= headerLen && b[0]&0xC0 == 0 && binary.BigEndian.Uint32(b[4:8]) == cookie &&
		int(binary.BigEndian.Uint16(b[2:4]))+headerLen <= len(b)
}

// Request builds a binding request.
func Request(tx TxID) []byte {
	b := make([]byte, headerLen)
	binary.BigEndian.PutUint16(b[0:2], bindingRequest)
	binary.BigEndian.PutUint32(b[4:8], cookie)
	copy(b[8:20], tx[:])
	return b
}

// ParseRequest reports whether b is a binding request, and its ID.
func ParseRequest(b []byte) (TxID, bool) {
	var t TxID
	if !isSTUN(b) || binary.BigEndian.Uint16(b[0:2]) != bindingRequest {
		return t, false
	}
	copy(t[:], b[8:20])
	return t, true
}

// Response builds the success response telling the asker its address.
func Response(tx TxID, addr netip.AddrPort) []byte {
	ip := addr.Addr().Unmap()
	fam, ipLen := byte(familyIPv4), 4
	if ip.Is6() {
		fam, ipLen = familyIPv6, 16
	}
	attrLen := 4 + ipLen
	b := make([]byte, headerLen+4+attrLen)
	binary.BigEndian.PutUint16(b[0:2], bindingSuccess)
	binary.BigEndian.PutUint16(b[2:4], uint16(4+attrLen))
	binary.BigEndian.PutUint32(b[4:8], cookie)
	copy(b[8:20], tx[:])
	a := b[headerLen:]
	binary.BigEndian.PutUint16(a[0:2], attrXORMapped)
	binary.BigEndian.PutUint16(a[2:4], uint16(attrLen))
	a[5] = fam
	binary.BigEndian.PutUint16(a[6:8], addr.Port()^uint16(cookie>>16))
	raw := ip.AsSlice()
	key := xorKey(tx)
	for i := range raw {
		a[8+i] = raw[i] ^ key[i]
	}
	return b
}

func xorKey(tx TxID) [16]byte {
	var k [16]byte
	binary.BigEndian.PutUint32(k[0:4], cookie)
	copy(k[4:], tx[:])
	return k
}

// ParseResponse returns the mapped address of a success response to tx.
func ParseResponse(b []byte, tx TxID) (netip.AddrPort, bool) {
	if !isSTUN(b) || binary.BigEndian.Uint16(b[0:2]) != bindingSuccess || [12]byte(b[8:20]) != tx {
		return netip.AddrPort{}, false
	}
	end := headerLen + int(binary.BigEndian.Uint16(b[2:4]))
	for p := headerLen; p+4 <= end; {
		typ, l := binary.BigEndian.Uint16(b[p:p+2]), int(binary.BigEndian.Uint16(b[p+2:p+4]))
		v := p + 4
		if v+l > end {
			break
		}
		if typ == attrXORMapped && l >= 8 {
			port := binary.BigEndian.Uint16(b[v+2:v+4]) ^ uint16(cookie>>16)
			key := xorKey(tx)
			n := 4
			if b[v+1] == familyIPv6 {
				n = 16
			}
			if l < 4+n {
				break
			}
			raw := make([]byte, n)
			for i := range raw {
				raw[i] = b[v+4+i] ^ key[i]
			}
			ip, ok := netip.AddrFromSlice(raw)
			if !ok {
				break
			}
			return netip.AddrPortFrom(ip.Unmap(), port), true
		}
		p = v + (l+3)&^3
	}
	return netip.AddrPort{}, false
}
