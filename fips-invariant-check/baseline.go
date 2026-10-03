package main

import (
	_ "embed"
	"fmt"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"
)

//go:embed baseline.env
var embeddedBaseline string

// baseline is the fleet-wide OpenSSL major and FIPS provider identity every image must match.
type baseline struct {
	OpenSSLMajor      string // "3" means libcrypto.so.3
	ProviderName      string // OSSL_PROV_PARAM_NAME of the one fips.so
	ProviderBuildinfo string // OSSL_PROV_PARAM_BUILDINFO of the one fips.so
	CMVP              string // certificate, for the report only
}

// parseBaseline reads KEY=VALUE lines ('#' comments, optional double quotes). Every key is required.
func parseBaseline(s string) (*baseline, error) {
	known := map[string]bool{"FIPS_OPENSSL_MAJOR": true, "FIPS_PROVIDER_NAME": true, "FIPS_PROVIDER_BUILDINFO": true, "FIPS_PROVIDER_CMVP": true}
	kv := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("baseline: %q is not KEY=VALUE", line)
		}
		k = strings.TrimSpace(k)
		if !known[k] {
			return nil, fmt.Errorf("baseline: unknown key %s", k)
		}
		if _, dup := kv[k]; dup {
			return nil, fmt.Errorf("baseline: %s is set twice", k)
		}
		kv[k] = strings.Trim(strings.TrimSpace(v), `"`)
	}
	b := &baseline{kv["FIPS_OPENSSL_MAJOR"], kv["FIPS_PROVIDER_NAME"], kv["FIPS_PROVIDER_BUILDINFO"], kv["FIPS_PROVIDER_CMVP"]}
	for k, v := range map[string]string{"FIPS_OPENSSL_MAJOR": b.OpenSSLMajor, "FIPS_PROVIDER_NAME": b.ProviderName,
		"FIPS_PROVIDER_BUILDINFO": b.ProviderBuildinfo, "FIPS_PROVIDER_CMVP": b.CMVP} {
		if v == "" {
			return nil, fmt.Errorf("baseline: %s is missing", k)
		}
	}
	if !regexp.MustCompile(`^[0-9]+$`).MatchString(b.OpenSSLMajor) {
		return nil, fmt.Errorf("baseline: FIPS_OPENSSL_MAJOR %q is not a number", b.OpenSSLMajor)
	}
	return b, nil
}

// Provider identity as compiled into fips.so: the name and build-info C strings that
// OSSL_PROV_PARAM_NAME and OSSL_PROV_PARAM_BUILDINFO return.
var (
	providerNameString  = regexp.MustCompile(`\x00([A-Za-z][A-Za-z0-9 .-]*FIPS Provider for OpenSSL)\x00`)
	providerBuildString = regexp.MustCompile(`\x00([0-9]+\.[0-9]+\.[0-9]+-r[0-9]+)\x00`)
)

func providerIdentity(realPath string) (names, builds []string, err error) {
	data, err := os.ReadFile(realPath)
	if err != nil {
		return nil, nil, err
	}
	for _, m := range providerNameString.FindAllSubmatch(data, -1) {
		names = append(names, string(m[1]))
	}
	for _, m := range providerBuildString.FindAllSubmatch(data, -1) {
		builds = append(builds, string(m[1]))
	}
	slices.Sort(names)
	slices.Sort(builds)
	return slices.Compact(names), slices.Compact(builds), nil
}

// isProviderModule: an OpenSSL FIPS provider module, by name anywhere in the image. OpenSSL loads
// it from MODULESDIR, which a build or OPENSSL_MODULES can point anywhere, so location proves nothing.
func isProviderModule(imagePath string) bool {
	return path.Base(imagePath) == "fips.so"
}
