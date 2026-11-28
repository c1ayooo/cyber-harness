package egress

import (
	"context"
	"net"
)

// Dial is one outbound dialer. It mirrors proxyclient.Dial structurally so
// neither side of the registry must import the other: 4zfence converts a
// proxyclient.Dial into this type when registering, and the proxy hub
// converts it back when dialing. A capability without proxyclient linked
// (core is dependency-light by design) can still hold and hand off the value.
type Dial func(ctx context.Context, network, address string) (net.Conn, error)
