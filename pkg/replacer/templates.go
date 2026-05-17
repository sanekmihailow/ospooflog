package replacer

import (
	"fmt"
	"strings"

	"github.com/sanekmihailow/ospooflog/pkg/detector"
)

// templates maps each entity kind to a builder function. The builder gets
// the per-kind 1-based counter and optional extras pulled from the
// original match (port for ADDR, scheme/host/port/db for DSN).
var templates = map[detector.EntityKind]func(n int, extra map[string]string) string{
	detector.KindIP: func(n int, _ map[string]string) string {
		return fmt.Sprintf("192.168.1.%d", n)
	},
	detector.KindIP6: func(n int, _ map[string]string) string {
		return fmt.Sprintf("fd00::%x", n)
	},
	detector.KindMAC: func(n int, _ map[string]string) string {
		// IEEE locally-administered range (second hex digit of first octet
		// is 2/6/A/E). 02:xx is safe and obviously fake.
		return fmt.Sprintf("02:00:00:00:%02x:%02x", (n>>8)&0xff, n&0xff)
	},
	detector.KindAddr: func(n int, extra map[string]string) string {
		port := extra["port"]
		if port == "" {
			port = "8080"
		}
		// Preserve the original port — AI needs to know it's PostgreSQL (5432)
		// vs HTTPS (443) vs Redis (6379) for the advice to be useful.
		return fmt.Sprintf("192.168.1.%d:%s", n, port)
	},
	detector.KindHost: func(n int, _ map[string]string) string {
		return fmt.Sprintf("myhost%d.local", n)
	},
	detector.KindFQDN: func(n int, _ map[string]string) string {
		return fmt.Sprintf("service%d.example.com", n)
	},
	detector.KindUser: func(n int, _ map[string]string) string {
		return fmt.Sprintf("user%d", n)
	},
	detector.KindEmail: func(n int, _ map[string]string) string {
		return fmt.Sprintf("user%d@example.com", n)
	},
	detector.KindPort: func(n int, _ map[string]string) string {
		ports := []string{"8080", "8081", "9090", "9091", "3000", "4000"}
		return ":" + ports[(n-1)%len(ports)]
	},
	detector.KindPath: func(n int, _ map[string]string) string {
		return fmt.Sprintf("/var/lib/myapp%d/data", n)
	},
	detector.KindUUID: func(n int, _ map[string]string) string {
		return fmt.Sprintf("00000000-0000-0000-0000-%012d", n)
	},
	detector.KindToken: func(n int, _ map[string]string) string {
		// Fake JWT-shaped string. Header decodes to {"alg":"HS256"},
		// payload is meaningless, signature is "fakesigNNNN" so it stays
		// recognisable as a fake.
		return fmt.Sprintf("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyJWQifQ.fakesig%04d", n)
	},
	detector.KindPassword: func(n int, _ map[string]string) string {
		return fmt.Sprintf("FAKE_PASSWORD_%03d", n)
	},
	detector.KindFingerprint: func(n int, _ map[string]string) string {
		// Shape-preserving fake: 43-char base64-ish blob after "SHA256:".
		body := strings.Repeat("0", 39)
		return fmt.Sprintf("SHA256:%s%04d", body, n)
	},
	detector.KindPubKey: func(n int, _ map[string]string) string {
		return fmt.Sprintf("ssh-rsa AAAAFAKEPUBKEY%04d", n)
	},
	detector.KindPrivKey: func(n int, _ map[string]string) string {
		return fmt.Sprintf("-----BEGIN OPENSSH PRIVATE KEY-----\nFAKE_PRIVATE_KEY_%03d\n-----END OPENSSH PRIVATE KEY-----", n)
	},
	detector.KindDSN: func(n int, extra map[string]string) string {
		scheme := extra["scheme"]
		if scheme == "" {
			scheme = "postgres"
		}
		port := extra["port"]
		if port == "" {
			port = defaultPortForScheme(scheme)
		}
		return fmt.Sprintf("%s://user%d:strong_password@localhost:%s/mydb%d", scheme, n, port, n)
	},
}

func defaultPortForScheme(scheme string) string {
	switch scheme {
	case "mysql":
		return "3306"
	case "redis":
		return "6379"
	case "mongodb", "mongodb+srv":
		return "27017"
	case "amqp", "amqps":
		return "5672"
	case "kafka":
		return "9092"
	default:
		return "5432"
	}
}
