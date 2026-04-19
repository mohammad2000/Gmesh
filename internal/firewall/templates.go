package firewall

// Templates is the canned library of rule presets. Each name maps to an
// ordered slice of Rules that operators can apply via `gmeshctl firewall
// templates apply <name>` or via the ApplyFirewallTemplate RPC.
//
// Templates start from a deny-by-default posture (caller picks the default
// policy); each template adds the allow-list matching its intent.
var Templates = map[string][]Rule{

	// SSH-only: allow TCP/22 from mesh, drop everything else.
	"ssh-only": {
		{
			ID: 1, Name: "allow ssh (mesh)", Enabled: true, Priority: 100,
			Action: ActionAllow, Protocol: ProtoTCP, PortRange: "22",
			Source: "10.200.0.0/16", Direction: DirectionInbound,
			ConnState: "NEW,ESTABLISHED",
		},
		{
			ID: 2, Name: "allow established", Enabled: true, Priority: 200,
			Action: ActionAllow, Protocol: ProtoAny,
			Direction: DirectionInbound, ConnState: "ESTABLISHED,RELATED",
		},
	},

	// HTTP/S web server: allow 80+443 from anywhere.
	"web-server": {
		{
			ID: 1, Name: "allow http", Enabled: true, Priority: 100,
			Action: ActionAllow, Protocol: ProtoTCP, PortRange: "80",
			Direction: DirectionInbound, ConnState: "NEW,ESTABLISHED",
		},
		{
			ID: 2, Name: "allow https", Enabled: true, Priority: 101,
			Action: ActionAllow, Protocol: ProtoTCP, PortRange: "443",
			Direction: DirectionInbound, ConnState: "NEW,ESTABLISHED",
		},
	},

	// Postgres internal: 5432 from mesh only.
	"postgres": {
		{
			ID: 1, Name: "allow pg mesh", Enabled: true, Priority: 100,
			Action: ActionAllow, Protocol: ProtoTCP, PortRange: "5432",
			Source: "10.200.0.0/16", Direction: DirectionInbound,
			ConnState: "NEW,ESTABLISHED",
		},
	},

	// DNS resolver: 53 TCP+UDP.
	"dns": {
		{
			ID: 1, Name: "allow dns udp", Enabled: true, Priority: 100,
			Action: ActionAllow, Protocol: ProtoUDP, PortRange: "53",
			Direction: DirectionInbound,
		},
		{
			ID: 2, Name: "allow dns tcp", Enabled: true, Priority: 101,
			Action: ActionAllow, Protocol: ProtoTCP, PortRange: "53",
			Direction: DirectionInbound,
		},
	},

	// Ratelimited SSH: accepts SSH but throttles new connections to
	// 5/minute per source IP (good default against brute force).
	"ssh-ratelimit": {
		{
			ID: 1, Name: "allow ssh rate-limited", Enabled: true, Priority: 100,
			Action: ActionAllow, Protocol: ProtoTCP, PortRange: "22",
			Direction: DirectionInbound, ConnState: "NEW",
			RateLimit: "5/m", RateBurst: 10,
		},
		{
			ID: 2, Name: "allow established", Enabled: true, Priority: 200,
			Action: ActionAllow, Protocol: ProtoAny,
			Direction: DirectionInbound, ConnState: "ESTABLISHED,RELATED",
		},
	},

	// Mesh-only lockdown: only permit traffic from 10.200.0.0/16.
	"mesh-only": {
		{
			ID: 1, Name: "allow mesh", Enabled: true, Priority: 100,
			Action: ActionAllow, Protocol: ProtoAny,
			Source: "10.200.0.0/16", Direction: DirectionInbound,
		},
	},
}

// TemplateNames returns the sorted list of available template names for
// CLI help output.
func TemplateNames() []string {
	names := make([]string, 0, len(Templates))
	for n := range Templates {
		names = append(names, n)
	}
	// Simple in-place sort (avoid pulling sort package for one call).
	for i := 1; i < len(names); i++ {
		for j := i; j > 0 && names[j] < names[j-1]; j-- {
			names[j], names[j-1] = names[j-1], names[j]
		}
	}
	return names
}

// GetTemplate returns a defensive copy of the named template.
func GetTemplate(name string) ([]Rule, bool) {
	rules, ok := Templates[name]
	if !ok {
		return nil, false
	}
	out := make([]Rule, len(rules))
	copy(out, rules)
	return out, true
}
