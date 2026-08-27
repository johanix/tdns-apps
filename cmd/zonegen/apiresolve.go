/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Finding the tdns-auth management API without being told a third time.
 *
 * On a host that runs tdns-auth, the connection details already exist twice:
 * once in the server's own config (tdns-auth.yaml, which declares the address
 * it listens on and the key it accepts) and usually again in tdns-cli.yaml,
 * which is a client config of exactly the shape this tool wants. Making the
 * operator paste them a third time into tdns-zonegen.yaml is busywork.
 *
 * So the details can come from any of three places, and the resolution is
 * always REPORTED rather than silent: this tool creates key material, and
 * quietly resolving to the wrong keystore is not a mistake that should be
 * possible to make by accident.
 */

package main

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// conventionalAuthServer is the name tdns-cli.sample.yaml gives the
// authoritative server. Note it is NOT "tdns-auth" -- matching on the word
// "auth" finds nothing in a stock config.
const conventionalAuthServer = "tdns-server"

// Standard locations, tried in order when nothing was specified. tdns-cli.yaml
// comes first: it is already a client config, so it needs no derivation and no
// guessing about listen addresses or trust anchors.
var defaultApiConfigs = []struct {
	path   string
	isAuth bool
}{
	{"/etc/tdns/tdns-cli.yaml", false},
	{"/etc/tdns/tdns-auth.yaml", true},
}

// ApiOptions carries the connection-related flags, which every generator that
// signs shares.
type ApiOptions struct {
	AuthFile   string // --tdns-auth: derive from the SERVER's config
	CliFile    string // --tdns-cli:  lift from a client config
	ServerName string // --apiserver: which entry, when a client config has several
}

// AddApiFlags registers the connection flags on a generator command.
func (o *ApiOptions) AddApiFlags(fs interface {
	StringVar(*string, string, string, string)
}) {
	fs.StringVar(&o.AuthFile, "tdns-auth", "",
		"derive the API connection from a tdns-auth server config")
	fs.StringVar(&o.CliFile, "tdns-cli", "",
		"take the API connection from a tdns-cli client config")
	fs.StringVar(&o.ServerName, "apiserver", "",
		"which apiservers: entry to use, when there are several")
}

// minimal views of the two foreign config files. Deliberately NOT parsed with
// KnownFields: these files are full of keys that are none of our business, and
// rejecting them would make this fail on every real config.
type tdnsCliView struct {
	ApiServers []ApiServerConf `yaml:"apiservers"`
}

type tdnsAuthView struct {
	ApiServer struct {
		Addresses []string `yaml:"addresses"`
		ApiKey    string   `yaml:"apikey"`
		CertFile  string   `yaml:"certfile"`
		KeyFile   string   `yaml:"keyfile"`
	} `yaml:"apiserver"`
}

// ResolveApiServer returns the connection to use and a one-line description of
// where it came from, for printing. Precedence: an explicit flag, then this
// tool's own apiservers: block, then the standard locations.
func ResolveApiServer(c *Config, o ApiOptions) (ApiServerConf, string, error) {
	switch {
	case o.AuthFile != "" && o.CliFile != "":
		return ApiServerConf{}, "", fmt.Errorf(
			"--tdns-auth and --tdns-cli are alternatives; give one")

	case o.AuthFile != "":
		s, err := fromAuthConfig(o.AuthFile)
		return s, "derived from " + o.AuthFile, err

	case o.CliFile != "":
		s, err := fromCliConfig(o.CliFile, o.ServerName)
		return s, "from " + o.CliFile, err

	case len(c.ApiServers) > 0:
		s, err := pickServer(c.ApiServers, o.ServerName, "the zonegen config")
		return s, "from the zonegen config", err
	}

	for _, d := range defaultApiConfigs {
		if _, err := os.Stat(d.path); err != nil {
			continue
		}
		if d.isAuth {
			s, err := fromAuthConfig(d.path)
			return s, "derived from " + d.path + " (found automatically)", err
		}
		s, err := fromCliConfig(d.path, o.ServerName)
		return s, "from " + d.path + " (found automatically)", err
	}

	return ApiServerConf{}, "", fmt.Errorf(
		"no API connection: pass --tdns-auth or --tdns-cli, or declare apiservers: "+
			"in the zonegen config (looked for %s)",
		strings.Join([]string{defaultApiConfigs[0].path, defaultApiConfigs[1].path}, " and "))
}

func fromCliConfig(path, name string) (ApiServerConf, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return ApiServerConf{}, fmt.Errorf("reading %s: %v", path, err)
	}
	var v tdnsCliView
	if err := yaml.Unmarshal(data, &v); err != nil {
		return ApiServerConf{}, fmt.Errorf("parsing %s: %v", path, err)
	}
	if len(v.ApiServers) == 0 {
		return ApiServerConf{}, fmt.Errorf("%s declares no apiservers:", path)
	}
	return pickServer(v.ApiServers, name, path)
}

// pickServer resolves which entry to use. With one entry there is nothing to
// decide; with several it takes the requested name, or the conventional one,
// and otherwise refuses -- listing what it saw, because guessing which server
// to create keys in is exactly the wrong thing to do quietly.
func pickServer(servers []ApiServerConf, name, where string) (ApiServerConf, error) {
	if name != "" {
		for _, s := range servers {
			if strings.EqualFold(s.Name, name) {
				return s, nil
			}
		}
		return ApiServerConf{}, fmt.Errorf("%s has no apiservers: entry named %q (has %s)",
			where, name, strings.Join(serverNames(servers), ", "))
	}
	if len(servers) == 1 {
		return servers[0], nil
	}
	for _, s := range servers {
		if strings.EqualFold(s.Name, conventionalAuthServer) {
			return s, nil
		}
	}
	return ApiServerConf{}, fmt.Errorf(
		"%s declares %d apiservers: and none is named %q; pass --apiserver with one of: %s",
		where, len(servers), conventionalAuthServer, strings.Join(serverNames(servers), ", "))
}

func serverNames(servers []ApiServerConf) []string {
	out := make([]string, 0, len(servers))
	for _, s := range servers {
		out = append(out, s.Name)
	}
	sort.Strings(out)
	return out
}

// fromAuthConfig derives a client connection from the SERVER's own config.
//
// Two things need care. The listen address may be a wildcard, which is a fine
// thing to bind and a useless thing to dial, so an unspecified host becomes
// loopback. And certfile is the server's own certificate, not a CA: it works as
// a trust anchor when the cert is self-signed (the common case for a lab), and
// not at all when it was issued by a CA -- which the server config does not
// name anywhere. That case needs rootcafile set explicitly, so say so rather
// than failing later inside a TLS handshake.
func fromAuthConfig(path string) (ApiServerConf, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return ApiServerConf{}, fmt.Errorf("reading %s: %v", path, err)
	}
	var v tdnsAuthView
	if err := yaml.Unmarshal(data, &v); err != nil {
		return ApiServerConf{}, fmt.Errorf("parsing %s: %v", path, err)
	}
	a := v.ApiServer
	if len(a.Addresses) == 0 {
		return ApiServerConf{}, fmt.Errorf("%s: apiserver.addresses is empty, "+
			"so there is no address to connect to", path)
	}
	if a.ApiKey == "" {
		return ApiServerConf{}, fmt.Errorf("%s: apiserver.apikey is empty", path)
	}

	hostport, err := dialableAddress(a.Addresses[0])
	if err != nil {
		return ApiServerConf{}, fmt.Errorf("%s: apiserver.addresses[0]: %v", path, err)
	}
	scheme := "http"
	if a.CertFile != "" {
		scheme = "https"
	}
	return ApiServerConf{
		Name:       conventionalAuthServer,
		BaseUrl:    fmt.Sprintf("%s://%s/api/v1", scheme, hostport),
		ApiKey:     a.ApiKey,
		AuthMethod: "X-API-Key",
		// Self-signed is the lab case and this is then the right anchor. If the
		// cert came from a CA this will not verify, and the operator has to
		// name the CA -- which is not derivable from the server's config.
		RootCAFile: a.CertFile,
	}, nil
}

// dialableAddress turns a listen address into one that can be connected to.
func dialableAddress(addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("%q is not host:port: %v", addr, err)
	}
	if port == "" {
		return "", fmt.Errorf("%q has no port", addr)
	}
	// "", 0.0.0.0 and :: all mean "every interface" -- bindable, not dialable.
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port), nil
}
