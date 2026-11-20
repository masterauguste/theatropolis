package pool

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// ParseOutboundURI converts a common proxy share URI into a sing-box outbound.
// The returned remark is the URI fragment, when present.
func ParseOutboundURI(value string) (json.RawMessage, string, error) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > MaxManualOutboundBytes {
		return nil, "", ErrInvalidOutbound
	}
	if strings.HasPrefix(strings.ToLower(value), "vmess://") {
		return parseVMessURI(value)
	}
	u, err := url.Parse(value)
	if err != nil || u.Scheme == "" {
		return nil, "", ErrInvalidOutbound
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme == "hy2" {
		scheme = "hysteria2"
	}
	if scheme == "ss" {
		return parseShadowsocksURI(u)
	}
	port, err := uriPort(u)
	if err != nil {
		return nil, "", err
	}
	out := map[string]any{"type": scheme, "server": u.Hostname(), "server_port": port}
	username, password := uriCredentials(u)
	query := u.Query()
	switch scheme {
	case "socks", "http":
		if username != "" {
			out["username"] = username
		}
		if password != "" {
			out["password"] = password
		}
	case "https":
		out["type"] = "http"
		if username != "" {
			out["username"] = username
		}
		if password != "" {
			out["password"] = password
		}
		out["tls"] = tlsFromQuery(query, u.Hostname(), true)
	case "trojan", "anytls", "hysteria2":
		secret := username
		if password != "" {
			secret = password
		}
		if secret == "" {
			return nil, "", ErrInvalidOutbound
		}
		out["password"] = secret
		out["tls"] = tlsFromQuery(query, u.Hostname(), true)
		if scheme == "hysteria2" && query.Get("obfs") != "" {
			out["obfs"] = map[string]any{
				"type": query.Get("obfs"), "password": firstQuery(query, "obfs-password", "obfs_password"),
			}
		}
	case "vless":
		if username == "" {
			return nil, "", ErrInvalidOutbound
		}
		out["uuid"] = username
		if flow := query.Get("flow"); flow != "" {
			out["flow"] = flow
		}
		if query.Get("security") == "tls" || query.Get("sni") != "" {
			out["tls"] = tlsFromQuery(query, u.Hostname(), true)
		}
		if transport, err := transportFromQuery(query); err != nil {
			return nil, "", err
		} else if transport != nil {
			out["transport"] = transport
		}
	case "tuic":
		if username == "" || password == "" {
			return nil, "", ErrInvalidOutbound
		}
		out["uuid"], out["password"] = username, password
		out["tls"] = tlsFromQuery(query, u.Hostname(), true)
		if cc := firstQuery(query, "congestion_control", "congestion-control"); cc != "" {
			out["congestion_control"] = cc
		}
	case "shadowsocks": // Accept the descriptive alias too.
		if username == "" || password == "" {
			return nil, "", ErrInvalidOutbound
		}
		out["method"], out["password"] = username, password
	default:
		return nil, "", fmt.Errorf("%w: unsupported URI scheme %q", ErrInvalidOutbound, u.Scheme)
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		return nil, "", fmt.Errorf("%w: encode outbound", ErrInvalidOutbound)
	}
	return encoded, strings.TrimSpace(u.Fragment), nil
}

func parseShadowsocksURI(u *url.URL) (json.RawMessage, string, error) {
	method, password := uriCredentials(u)
	// Legacy Shadowsocks links encode the complete method:password@host:port
	// authority, while SIP002 links encode only the user info (or not at all).
	if method == "" && password == "" && u.Port() == "" {
		if decoded, err := decodeBase64(u.Host); err == nil {
			legacy, parseErr := url.Parse("ss://" + string(decoded))
			if parseErr == nil {
				legacy.Fragment = u.Fragment
				u = legacy
				method, password = uriCredentials(u)
			}
		}
	}
	if password == "" && method != "" {
		if decoded, err := decodeBase64(method); err == nil {
			method, password, _ = strings.Cut(string(decoded), ":")
		}
	}
	if method == "" || password == "" {
		return nil, "", ErrInvalidOutbound
	}
	port, err := uriPort(u)
	if err != nil {
		return nil, "", err
	}
	out := map[string]any{"type": "shadowsocks", "server": u.Hostname(), "server_port": port, "method": method, "password": password}
	encoded, _ := json.Marshal(out)
	return encoded, strings.TrimSpace(u.Fragment), nil
}

func parseVMessURI(value string) (json.RawMessage, string, error) {
	payload := value[8:]
	decoded, err := decodeBase64(payload)
	if err != nil {
		return nil, "", ErrInvalidOutbound
	}
	var source struct {
		Address  string `json:"add"`
		Port     any    `json:"port"`
		UUID     string `json:"id"`
		Security string `json:"scy"`
		TLS      string `json:"tls"`
		SNI      string `json:"sni"`
		Network  string `json:"net"`
		Host     string `json:"host"`
		Path     string `json:"path"`
		Remark   string `json:"ps"`
	}
	if err := json.Unmarshal(decoded, &source); err != nil || source.Address == "" || source.UUID == "" {
		return nil, "", ErrInvalidOutbound
	}
	port, err := strconv.Atoi(fmt.Sprint(source.Port))
	if err != nil || port < 1 || port > 65535 {
		return nil, "", ErrInvalidOutbound
	}
	out := map[string]any{"type": "vmess", "server": source.Address, "server_port": port, "uuid": source.UUID, "security": source.Security}
	if source.TLS != "" && source.TLS != "none" {
		out["tls"] = map[string]any{"enabled": true, "server_name": firstNonempty(source.SNI, source.Host, source.Address)}
	}
	if source.Network != "" && source.Network != "tcp" {
		q := url.Values{"type": {source.Network}, "host": {source.Host}, "path": {source.Path}}
		transport, err := transportFromQuery(q)
		if err != nil {
			return nil, "", err
		}
		out["transport"] = transport
	}
	encoded, _ := json.Marshal(out)
	return encoded, strings.TrimSpace(source.Remark), nil
}

func uriPort(u *url.URL) (int, error) {
	if u.Hostname() == "" || u.Port() == "" {
		return 0, ErrInvalidOutbound
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 || net.ParseIP(u.Hostname()) == nil && strings.ContainsAny(u.Hostname(), " /?#") {
		return 0, ErrInvalidOutbound
	}
	return port, nil
}

func uriCredentials(u *url.URL) (string, string) {
	if u.User == nil {
		return "", ""
	}
	password, _ := u.User.Password()
	return u.User.Username(), password
}

func tlsFromQuery(q url.Values, host string, enabled bool) map[string]any {
	tls := map[string]any{"enabled": enabled}
	if serverName := firstQuery(q, "sni", "peer", "server_name"); serverName != "" {
		tls["server_name"] = serverName
	} else {
		tls["server_name"] = host
	}
	if queryBool(q, "insecure", "allowInsecure", "allow_insecure") {
		tls["insecure"] = true
	}
	if alpn := q.Get("alpn"); alpn != "" {
		tls["alpn"] = strings.Split(alpn, ",")
	}
	return tls
}

func transportFromQuery(q url.Values) (map[string]any, error) {
	kind := firstQuery(q, "type", "net")
	if kind == "" || kind == "tcp" {
		return nil, nil
	}
	transport := map[string]any{"type": kind}
	switch kind {
	case "ws", "httpupgrade":
		if path := q.Get("path"); path != "" {
			transport["path"] = path
		}
		if host := q.Get("host"); host != "" {
			transport["headers"] = map[string]any{"Host": host}
		}
	case "grpc":
		if service := firstQuery(q, "serviceName", "service_name"); service != "" {
			transport["service_name"] = service
		}
	default:
		return nil, fmt.Errorf("%w: unsupported transport %q", ErrInvalidOutbound, kind)
	}
	return transport, nil
}

func queryBool(q url.Values, names ...string) bool {
	value := strings.ToLower(firstQuery(q, names...))
	return value == "1" || value == "true" || value == "yes"
}

func firstQuery(q url.Values, names ...string) string {
	for _, name := range names {
		if value := q.Get(name); value != "" {
			return value
		}
	}
	return ""
}
func firstNonempty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
func decodeBase64(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	for _, encoding := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		if decoded, err := encoding.DecodeString(value); err == nil {
			return decoded, nil
		}
	}
	return nil, errors.New("invalid base64")
}
