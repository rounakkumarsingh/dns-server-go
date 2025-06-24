package dns

import "fmt"

type Class uint16

var ClassType = struct {
	IN Class
	CS Class
	CH Class
	HS Class
}{
	IN: 1,
	CS: 2,
	CH: 3,
	HS: 4,
}

var ClassName = map[Class]string{
	ClassType.IN: "Internet",
	ClassType.CS: "CSNET Class",
	ClassType.CH: "CHAOS",
	ClassType.HS: "HESIOD",
}

func (c Class) String() string {
	val, ok := ClassName[c]
	if ok {
		return val
	}
	return fmt.Sprintf("%d", uint16(c))
}
