package GoSNMPServer

import (
	"bytes"
	"strconv"
	"strings"

	"github.com/slayercat/gosnmp"
)

func getPktContextOrCommunity(i *gosnmp.SnmpPacket) string {
	if i.Version == gosnmp.Version3 {
		return i.ContextName
	} else {
		return i.Community
	}
}

func copySnmpPacket(i *gosnmp.SnmpPacket) gosnmp.SnmpPacket {
	var ret gosnmp.SnmpPacket = *i
	if i.SecurityParameters != nil {
		ret.SecurityParameters = i.SecurityParameters.Copy()
	}
	return ret
}

func oidToByteString(oid string) string {
	oid = strings.TrimLeft(oid, ".")

	components := strings.Split(oid, ".")
	obj := make([]int, len(components))
	for i, c := range components {
		num, err := strconv.Atoi(c)
		if err != nil {
			panic(err)
		}
		obj[i] = num
	}
	var buf bytes.Buffer
	for _, b := range obj {
		if b < 128 {
			buf.WriteByte(byte(b))
		} else {
			for b > 0 {
				buf.WriteByte(byte(0x80 | (b & 0x7f)))
				b >>= 7
			}
			buf.Bytes()[buf.Len()-1] &= 0x7f
		}
	}
	return buf.String()
}

// IsValidObjectIdentifier will check a oid string is valid oid
func IsValidObjectIdentifier(oid string) (result bool) {
	defer func() {
		if err := recover(); err != nil {
			result = false
			return
		}
	}()
	if len(oid) == 0 {
		return false
	}
	oidToByteString(string(oid))
	return true
}
