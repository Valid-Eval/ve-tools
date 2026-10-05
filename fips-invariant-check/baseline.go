package main

import (
	"bytes"
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

// baseline is the fleet-wide set of OpenSSL majors and the FIPS provider builds an image may carry.
type baseline struct {
	OpenSSLMajors []string        // allowed majors; each image links exactly one of them ("3" means libcrypto.so.3)
	ProviderName  string          // OSSL_PROV_PARAM_NAME every provider module must report
	Providers     []providerBuild // allowed OSSL_PROV_PARAM_BUILDINFO values, each with its certificate
}

type providerBuild struct {
	Buildinfo string
	CMVP      string // certificate, for the report only
}

// providerFor returns the allowed build a module's compiled-in identity matches: exactly one name,
// the baseline's, and exactly one build, an allowed one. A module carrying two builds matches none.
func (b *baseline) providerFor(r *fileReport) (providerBuild, bool) {
	if !slices.Equal(r.ProviderNames, []string{b.ProviderName}) || len(r.ProviderBuilds) != 1 {
		return providerBuild{}, false
	}
	i := slices.IndexFunc(b.Providers, func(p providerBuild) bool { return p.Buildinfo == r.ProviderBuilds[0] })
	if i < 0 {
		return providerBuild{}, false
	}
	return b.Providers[i], true
}

func (b *baseline) providersString() string {
	s := make([]string, len(b.Providers))
	for i, p := range b.Providers {
		s[i] = fmt.Sprintf("build %s (CMVP #%s)", p.Buildinfo, p.CMVP)
	}
	return fmt.Sprintf("%q %s", b.ProviderName, strings.Join(s, " or "))
}

// parseBaseline reads KEY=VALUE lines ('#' comments, optional double quotes). Every key is required.
func parseBaseline(s string) (*baseline, error) {
	known := map[string]bool{"FIPS_OPENSSL_MAJORS": true, "FIPS_PROVIDER_NAME": true, "FIPS_PROVIDER_BUILDS": true}
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
	b := &baseline{OpenSSLMajors: strings.Fields(kv["FIPS_OPENSSL_MAJORS"]), ProviderName: kv["FIPS_PROVIDER_NAME"]}
	for _, k := range []string{"FIPS_OPENSSL_MAJORS", "FIPS_PROVIDER_NAME", "FIPS_PROVIDER_BUILDS"} {
		if strings.TrimSpace(kv[k]) == "" {
			return nil, fmt.Errorf("baseline: %s is missing", k)
		}
	}
	for _, f := range strings.Fields(kv["FIPS_PROVIDER_BUILDS"]) {
		build, cmvp, ok := strings.Cut(f, ":")
		if !ok || !providerBuildString.MatchString(build) || !regexp.MustCompile(`^[0-9]+$`).MatchString(cmvp) {
			return nil, fmt.Errorf("baseline: FIPS_PROVIDER_BUILDS entry %q is not BUILDINFO:CMVP (e.g. 3.4.0-r5:5132)", f)
		}
		if slices.ContainsFunc(b.Providers, func(p providerBuild) bool { return p.Buildinfo == build }) {
			return nil, fmt.Errorf("baseline: FIPS_PROVIDER_BUILDS lists %s twice", build)
		}
		b.Providers = append(b.Providers, providerBuild{build, cmvp})
	}
	for i, m := range b.OpenSSLMajors {
		if !regexp.MustCompile(`^[0-9]+$`).MatchString(m) {
			return nil, fmt.Errorf("baseline: FIPS_OPENSSL_MAJORS entry %q is not a number", m)
		}
		if slices.Contains(b.OpenSSLMajors[:i], m) {
			return nil, fmt.Errorf("baseline: FIPS_OPENSSL_MAJORS lists %s twice", m)
		}
	}
	return b, nil
}

// Provider identity as compiled into fips.so: the name and build-info C strings that
// OSSL_PROV_PARAM_NAME and OSSL_PROV_PARAM_BUILDINFO return.
var (
	providerNameString  = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9 .-]*FIPS Provider for OpenSSL$`)
	providerBuildString = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+-r[0-9]+$`)
)

func providerIdentity(realPath string) (names, builds []string, err error) {
	data, err := os.ReadFile(realPath)
	if err != nil {
		return nil, nil, err
	}
	// Each NUL-delimited piece is judged on its own, so adjacent strings cannot share a delimiter.
	for _, s := range bytes.Split(data, []byte{0}) {
		switch {
		case providerNameString.Match(s):
			names = append(names, string(s))
		case providerBuildString.Match(s):
			builds = append(builds, string(s))
		}
	}
	slices.Sort(names)
	slices.Sort(builds)
	return slices.Compact(names), slices.Compact(builds), nil
}

// isProviderModule: an OpenSSL FIPS provider module, by name anywhere in the image: fips.so, or a
// versioned fips-<version>.so (DU ships the CMVP #5523 provider as fips-3.6.0.so). OpenSSL loads
// it from MODULESDIR, which a build or OPENSSL_MODULES can point anywhere, so location proves nothing.
func isProviderModule(imagePath string) bool {
	return providerModuleName.MatchString(path.Base(imagePath))
}

var providerModuleName = regexp.MustCompile(`^fips(-[0-9]+(\.[0-9]+)*)?\.so$`)
