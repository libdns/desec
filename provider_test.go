// desc_test is an integration test for the desec provider, to run it a deSEC token is required.
//
// Run it using
//
//	go test . -token=<deSEC token> -domain=<test domain>
//
// The <test domain> must not exist prior to running the test. This is mainly to protect against
// modifications of domains that are in use already.
package desec_test

import (
	"bytes"
	gocmp "cmp"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/libdns/desec"
	"github.com/libdns/libdns"
	"github.com/libdns/libdns/libdnstest"
)

var (
	token  = flag.String("token", "", "deSEC token")
	domain = flag.String("domain", "", "Domain to test with of the form sld.tld, it must not exist prior to running this test")
)

var cmpRecord = cmp.Options{
	cmpopts.EquateComparable(netip.Addr{}),
	cmpopts.SortSlices(func(x0, y0 libdns.Record) bool {
		x, y := x0.RR(), y0.RR()
		if v := strings.Compare(x.Name, y.Name); v != 0 {
			return v < 0
		}
		if v := strings.Compare(x.Type, y.Type); v != 0 {
			return v < 0
		}
		if v := strings.Compare(x.Data, y.Data); v != 0 {
			return v < 0
		}
		return false
	}),
}

func httpDo(ctx context.Context, t *testing.T, method, url string, in []byte) ([]byte, int) {
	t.Helper()

	var r io.Reader
	if len(in) > 0 {
		r = bytes.NewReader(in)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, r)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Token "+*token)
	req.Header.Set("Accept", "application/json; charset=utf-8")
	if len(in) > 0 {
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
	}

	for {
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}

		if res.StatusCode == http.StatusTooManyRequests {
			retryAfterHeader := res.Header.Get("Retry-After")
			retryAfter, err := strconv.Atoi(retryAfterHeader)
			if err != nil {
				t.Fatal(err)
			}
			t.Log("rate limited, retrying after", retryAfter, "seconds")
			time.Sleep(time.Duration(retryAfter) * time.Second)
			continue
		}

		defer res.Body.Close()
		body, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		return body, res.StatusCode
	}
}

func putRRSets(t *testing.T, domain, content string) {
	t.Helper()

	url := fmt.Sprintf("https://desec.io/api/v1/domains/%s/rrsets/", url.PathEscape(domain))
	body, status := httpDo(t.Context(), t, "PUT", url, []byte(content))
	switch status {
	case http.StatusOK:
		// success
	default:
		t.Fatalf("unexpected status code: %d: %v", status, string(body))
		panic("never reached")
	}
}

func domainExists(t *testing.T, domain string) bool {
	t.Helper()

	url := fmt.Sprintf("https://desec.io/api/v1/domains/%s/", url.PathEscape(domain))
	body, status := httpDo(t.Context(), t, "GET", url, nil)
	switch status {
	case http.StatusOK:
		return true
	case http.StatusNotFound:
		return false
	default:
		t.Fatalf("unexpected status code: %d: %v", status, string(body))
		panic("never reached")
	}
}

func createDomain(t *testing.T, domain string) {
	t.Helper()

	if domainExists(t, domain) {
		t.Fatalf("domain %q exists, but it should not", domain)
	}

	payload, err := json.Marshal(struct {
		Name string `json:"name"`
	}{
		Name: domain,
	})
	if err != nil {
		t.Fatal(err)
	}

	url := "https://desec.io/api/v1/domains/"
	body, status := httpDo(t.Context(), t, "POST", url, payload)
	switch status {
	case http.StatusCreated:
		// success
	default:
		t.Fatalf("unexpected status code: %d: %v", status, string(body))
		panic("never reached")
	}
}

func deleteDomain(t *testing.T, domain string) {
	t.Helper()

	// deleteDomains is used to cleanup domains created in the test, it should not be affected by
	// cancellation of the test context, so use a non-cancelable context here.
	ctx := context.WithoutCancel(t.Context())

	url := fmt.Sprintf("https://desec.io/api/v1/domains/%s/", url.PathEscape(domain))
	body, status := httpDo(ctx, t, "DELETE", url, nil)
	switch status {
	case http.StatusNoContent:
		// success
	default:
		t.Fatalf("unexpected status code: %d: %v", status, string(body))
		panic("never reached")
	}
}

// setup performs all test setup
//   - skip the test if -domain or -token are not provided
//   - fail if the domain provided by -domain exists already
//   - create the domain and setup the deletion of the domain at the end of the test
//   - ensure that the domain contains only the specified rrsets
//   - returns a context that can be used in the test
func setup(t *testing.T, rrsets string) {
	t.Helper()

	if *token == "" || *domain == "" {
		t.Skip("skipping integration test; both -token and -domain must be set")
	}

	createDomain(t, *domain)
	t.Cleanup(func() { deleteDomain(t, *domain) })

	// A freshly created domain contains a default NS record. To make sure the domain only has
	// the rrsets specified in the call to setup we need to delete them first
	putRRSets(t, *domain, `[{"subname": "", "type": "NS", "ttl": 3600, "records": []}]`)
	putRRSets(t, *domain, rrsets)
}

func TestGetRecords(t *testing.T) {
	setup(t, `[
		{"subname": "", "type": "NS", "ttl": 3600, "records": []},
		{"subname": "", "type": "A", "ttl": 3601, "records": ["127.0.0.3"]},
		{"subname": "www", "type": "A", "ttl": 3600, "records": ["127.0.0.1", "127.0.0.2"]},
		{"subname": "subsub.sub", "type": "A", "ttl": 3600, "records": ["127.0.0.4"]},
		{"subname": "www", "type": "HTTPS", "ttl": 3600, "records": ["1 . alpn=\"h2\""]},
		{"subname": "", "type": "MX", "ttl": 3600, "records": ["0 mx0.example.com.", "10 mx1.example.com."]},
		{"subname": "_sip._tcp.sub", "type": "SRV", "ttl": 3600, "records": ["1 100 5061 sip.example.com."]},
		{"subname": "_ftp._tcp", "type": "URI", "ttl": 3600, "records": ["1 2 \"ftp://example.com/arst\""]},
		{"subname": "", "type": "TXT", "ttl": 3600, "records": ["\"hello dns!\""]}
	]`)

	p := &desec.Provider{
		Token: *token,
	}

	want := []libdns.Record{
		libdns.Address{
			Name: "@",
			IP:   netip.MustParseAddr("127.0.0.3"),
			TTL:  time.Second * 3601,
		},
		libdns.TXT{
			Name: "@",
			Text: `hello dns!`,
			TTL:  time.Second * 3600,
		},
		libdns.Address{
			Name: "www",
			IP:   netip.MustParseAddr("127.0.0.1"),
			TTL:  3600 * time.Second,
		},
		libdns.ServiceBinding{
			Scheme: "https",
			Name:   "www",
			Target: ".",
			Params: libdns.SvcParams{
				"alpn": []string{"h2"},
			},
			Priority: 1,
			TTL:      3600 * time.Second,
		},
		libdns.Address{
			Name: "www",
			IP:   netip.MustParseAddr("127.0.0.2"),
			TTL:  3600 * time.Second,
		},
		libdns.Address{
			Name: "subsub.sub",
			IP:   netip.MustParseAddr("127.0.0.4"),
			TTL:  3600 * time.Second,
		},
		libdns.MX{
			Name:       "@",
			Target:     "mx0.example.com.",
			TTL:        3600 * time.Second,
			Preference: 0,
		},
		libdns.MX{
			Name:       "@",
			Target:     "mx1.example.com.",
			TTL:        3600 * time.Second,
			Preference: 10,
		},
		libdns.SRV{
			Service:   "sip",
			Transport: "tcp",
			Name:      "sub",
			Weight:    100,
			Port:      5061,
			Target:    "sip.example.com.",
			TTL:       3600 * time.Second,
			Priority:  1,
		},
		libdns.RR{
			Type: "URI",
			Name: "_ftp._tcp",
			Data: `1 2 "ftp://example.com/arst"`,
			TTL:  3600 * time.Second,
		},
	}

	got, err := p.GetRecords(t.Context(), *domain+".")
	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(want, got, cmpRecord); diff != "" {
		t.Fatalf("p.GetRecords() unexpected diff [-want +got]: %s", diff)
	}
}

func TestSetRecords(t *testing.T) {
	setup(t, `[
		{"subname": "www", "type": "A", "ttl": 3600, "records": ["127.0.1.1", "127.0.1.2"]},
		{"subname": "", "type": "TXT", "ttl": 3600, "records": ["\"will be overridden\""]},
		{"subname": "sub", "type": "TXT", "ttl": 3600, "records": ["\"will stay the same\""]},
		{"subname": "www", "type": "HTTPS", "ttl": 3600, "records": ["1 . alpn=\"h2\""]},
		{"subname": "_sip._tcp.sub", "type": "SRV", "ttl": 3600, "records": ["1 100 5061 sip.example.com."]},
		{"subname": "_ftp._tcp", "type": "URI", "ttl": 3600, "records": ["1 2 \"ftp://example.com/arst\""]},
		{"subname": "", "type": "MX", "ttl": 3600, "records": ["0 mx0.example.com.", "10 mx1.example.com."]},
		{"subname": "www", "type": "NS", "ttl": 3600, "records": ["ns0.example.com.", "ns1.example.com."]}
	]`)

	p := &desec.Provider{
		Token: *token,
	}

	records := []libdns.Record{
		libdns.Address{
			Name: "@",
			IP:   netip.MustParseAddr("127.0.0.3"),
			TTL:  time.Second * 3601,
		},
		libdns.TXT{
			Name: "@",
			Text: `hello dns!`,
			TTL:  time.Second * 3600,
		},
		libdns.Address{
			Name: "www",
			IP:   netip.MustParseAddr("127.0.0.1"),
			TTL:  3600 * time.Second,
		},
		libdns.ServiceBinding{
			Scheme: "https",
			Name:   "www",
			Target: ".",
			Params: libdns.SvcParams{
				"alpn": []string{"h2"},
			},
			Priority: 1,
			TTL:      3600 * time.Second,
		},
		libdns.Address{
			Name: "www",
			IP:   netip.MustParseAddr("127.0.0.2"),
			TTL:  3600 * time.Second,
		},
		libdns.Address{
			Name: "subsub.sub",
			IP:   netip.MustParseAddr("127.0.0.5"),
			TTL:  3600 * time.Second,
		},
		libdns.MX{
			Name:       "@",
			Target:     "mx0.example.com.",
			TTL:        3600 * time.Second,
			Preference: 0,
		},
		libdns.MX{
			Name:       "@",
			Target:     "mx1.example.com.",
			TTL:        3600 * time.Second,
			Preference: 10,
		},
		libdns.SRV{
			Service:   "sip",
			Transport: "tcp",
			Name:      "sub",
			Target:    "sip.example.com.",
			TTL:       3600 * time.Second,
			Priority:  1,
			Weight:    100,
			Port:      5061,
		},
		libdns.RR{
			Type: "URI",
			Name: "_ftp._tcp",
			Data: `1 2 "ftp://example.com/arst"`,
			TTL:  3600 * time.Second,
		},
	}

	recordsSet, err := p.SetRecords(t.Context(), *domain+".", records)
	if err != nil {
		t.Fatal(err)
	}

	// All set records, including the ones that already existed, should be returned
	// by SetRecords.
	wantSet := []libdns.Record{
		libdns.Address{
			Name: "@",
			IP:   netip.MustParseAddr("127.0.0.3"),
			TTL:  time.Second * 3601,
		},
		libdns.TXT{
			Name: "@",
			Text: `hello dns!`,
			TTL:  time.Second * 3600,
		},
		libdns.Address{
			Name: "www",
			IP:   netip.MustParseAddr("127.0.0.1"),
			TTL:  3600 * time.Second,
		},
		libdns.ServiceBinding{
			Scheme: "https",
			Name:   "www",
			Target: ".",
			Params: libdns.SvcParams{
				"alpn": []string{"h2"},
			},
			Priority: 1,
			TTL:      3600 * time.Second,
		},
		libdns.Address{
			Name: "www",
			IP:   netip.MustParseAddr("127.0.0.2"),
			TTL:  3600 * time.Second,
		},
		libdns.Address{
			Name: "subsub.sub",
			IP:   netip.MustParseAddr("127.0.0.5"),
			TTL:  3600 * time.Second,
		},
		libdns.MX{
			Name:       "@",
			Target:     "mx0.example.com.",
			TTL:        3600 * time.Second,
			Preference: 0,
		},
		libdns.MX{
			Name:       "@",
			Target:     "mx1.example.com.",
			TTL:        3600 * time.Second,
			Preference: 10,
		},
		libdns.SRV{
			Service:   "sip",
			Transport: "tcp",
			Name:      "sub",
			Target:    "sip.example.com.",
			TTL:       3600 * time.Second,
			Priority:  1,
			Weight:    100,
			Port:      5061,
		},
		libdns.RR{
			Type: "URI",
			Name: "_ftp._tcp",
			Data: `1 2 "ftp://example.com/arst"`,
			TTL:  3600 * time.Second,
		},
	}

	if diff := cmp.Diff(wantSet, recordsSet, cmpRecord); diff != "" {
		t.Fatalf("p.SetRecords() unexpected diff [-want +got]: %s", diff)
	}

	wantCurrent := []libdns.Record{
		// Records for (name, type) pairs which were not present in the SetRecords input
		// should be unaffected.
		libdns.TXT{
			Name: "sub",
			Text: `will stay the same`,
			TTL:  time.Second * 3600,
		},
		libdns.NS{
			Name:   "www",
			Target: "ns0.example.com.",
			TTL:    time.Second * 3600,
		},
		libdns.NS{
			Name:   "www",
			Target: "ns1.example.com.",
			TTL:    time.Second * 3600,
		},
		// Records for (name, type) pairs which were present in the SetRecords input
		// should match the output of SetRecords.
		libdns.Address{
			Name: "@",
			IP:   netip.MustParseAddr("127.0.0.3"),
			TTL:  time.Second * 3601,
		},
		libdns.TXT{
			Name: "@",
			Text: `hello dns!`,
			TTL:  time.Second * 3600,
		},
		libdns.Address{
			Name: "www",
			IP:   netip.MustParseAddr("127.0.0.1"),
			TTL:  3600 * time.Second,
		},
		libdns.ServiceBinding{
			Scheme: "https",
			Name:   "www",
			Target: ".",
			Params: libdns.SvcParams{
				"alpn": []string{"h2"},
			},
			Priority: 1,
			TTL:      3600 * time.Second,
		},
		libdns.Address{
			Name: "www",
			IP:   netip.MustParseAddr("127.0.0.2"),
			TTL:  3600 * time.Second,
		},
		libdns.Address{
			Name: "subsub.sub",
			IP:   netip.MustParseAddr("127.0.0.5"),
			TTL:  3600 * time.Second,
		},
		libdns.MX{
			Name:       "@",
			Target:     "mx0.example.com.",
			TTL:        3600 * time.Second,
			Preference: 0,
		},
		libdns.MX{
			Name:       "@",
			Target:     "mx1.example.com.",
			TTL:        3600 * time.Second,
			Preference: 10,
		},
		libdns.SRV{
			Service:   "sip",
			Transport: "tcp",
			Name:      "sub",
			Target:    "sip.example.com.",
			TTL:       3600 * time.Second,
			Priority:  1,
			Weight:    100,
			Port:      5061,
		},
		libdns.RR{
			Type: "URI",
			Name: "_ftp._tcp",
			Data: `1 2 "ftp://example.com/arst"`,
			TTL:  3600 * time.Second,
		},
	}

	got, err := p.GetRecords(t.Context(), *domain+".")
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(wantCurrent, got, cmpRecord); diff != "" {
		t.Fatalf("p.GetRecords() unexpected diff [-want +got]: %s", diff)
	}
}

func TestAppendRecords(t *testing.T) {
	setup(t, `[
		{"subname": "www", "type": "A", "ttl": 3600, "records": ["127.0.0.1"]},
		{"subname": "", "type": "TXT", "ttl": 3600, "records": ["\"hello dns!\""]}
	]`)

	p := &desec.Provider{
		Token: *token,
	}

	append := []libdns.Record{
		libdns.Address{
			Name: "@",
			IP:   netip.MustParseAddr("127.0.0.3"),
			TTL:  time.Second * 3601,
		},
		libdns.TXT{
			Name: "@",
			Text: `hello dns!`,
			TTL:  time.Second * 3600,
		},
		libdns.Address{
			Name: "www",
			IP:   netip.MustParseAddr("127.0.0.2"),
			TTL:  3600 * time.Second,
		},
		libdns.Address{
			Name: "subsub.sub",
			IP:   netip.MustParseAddr("127.0.0.3"),
			TTL:  3600 * time.Second,
		},
	}

	added, err := p.AppendRecords(t.Context(), *domain+".", append)
	if err != nil {
		t.Fatal(err)
	}

	wantAdded := []libdns.Record{
		libdns.Address{
			Name: "@",
			IP:   netip.MustParseAddr("127.0.0.3"),
			TTL:  time.Second * 3601,
		},
		libdns.Address{
			Name: "www",
			IP:   netip.MustParseAddr("127.0.0.2"),
			TTL:  3600 * time.Second,
		},
		libdns.Address{
			Name: "subsub.sub",
			IP:   netip.MustParseAddr("127.0.0.3"),
			TTL:  3600 * time.Second,
		},
	}
	if diff := cmp.Diff(added, wantAdded, cmpRecord); diff != "" {
		t.Fatalf("p.SetRecords() unexpected diff [-want +got]: %s", diff)
	}

	got, err := p.GetRecords(t.Context(), *domain+".")
	if err != nil {
		t.Fatal(err)
	}

	want := []libdns.Record{
		libdns.Address{
			Name: "@",
			IP:   netip.MustParseAddr("127.0.0.3"),
			TTL:  time.Second * 3601,
		},
		libdns.TXT{
			Name: "@",
			Text: `hello dns!`,
			TTL:  time.Second * 3600,
		},
		libdns.Address{
			Name: "www",
			IP:   netip.MustParseAddr("127.0.0.1"),
			TTL:  3600 * time.Second,
		},
		libdns.Address{
			Name: "www",
			IP:   netip.MustParseAddr("127.0.0.2"),
			TTL:  3600 * time.Second,
		},
		libdns.Address{
			Name: "subsub.sub",
			IP:   netip.MustParseAddr("127.0.0.3"),
			TTL:  3600 * time.Second,
		},
	}
	if diff := cmp.Diff(want, got, cmpRecord); diff != "" {
		t.Fatalf("p.GetRecords() unexpected diff [-want +got]: %s", diff)
	}
}

func TestDeleteRecords(t *testing.T) {
	setup(t, `[
		{"subname": "www", "type": "A", "ttl": 3600, "records": ["127.0.0.1"]},
		{"subname": "", "type": "TXT", "ttl": 3600, "records": ["\"hello dns!\""]}
	]`)

	p := &desec.Provider{
		Token: *token,
	}

	delete := []libdns.Record{
		libdns.Address{
			Name: "@",
			IP:   netip.MustParseAddr("127.0.0.3"),
			TTL:  time.Second * 3601,
		},
		libdns.TXT{
			Name: "@",
			Text: `hello dns!`,
			TTL:  time.Second * 3600,
		},
	}

	deleted, err := p.DeleteRecords(t.Context(), *domain+".", delete)
	if err != nil {
		t.Fatal(err)
	}

	wantDeleted := []libdns.Record{
		libdns.TXT{
			Name: "@",
			Text: `hello dns!`,
			TTL:  time.Second * 3600,
		},
	}
	if diff := cmp.Diff(deleted, wantDeleted, cmpRecord); diff != "" {
		t.Fatalf("p.SetRecords() unexpected diff [-want +got]: %s", diff)
	}

	got, err := p.GetRecords(t.Context(), *domain+".")
	if err != nil {
		t.Fatal(err)
	}

	want := []libdns.Record{
		libdns.Address{
			Name: "www",
			IP:   netip.MustParseAddr("127.0.0.1"),
			TTL:  3600 * time.Second,
		},
	}
	if diff := cmp.Diff(want, got, cmpRecord); diff != "" {
		t.Fatalf("p.GetRecords() unexpected diff [-want +got]: %s", diff)
	}
}

func TestListZones(t *testing.T) {
	if *token == "" || *domain == "" {
		t.Skip("skipping integration test; both -token and -domain must be set")
	}

	p := &desec.Provider{
		Token: *token,
	}

	testDomains := map[string]bool{
		*domain:            true,
		"test1-" + *domain: true,
		"test2-" + *domain: true,
	}

	for testDomain := range testDomains {
		createDomain(t, testDomain)
		domain := testDomain
		t.Cleanup(func() { deleteDomain(t, domain) })
	}

	got, err := p.ListZones(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	var want []libdns.Zone
	for domain := range testDomains {
		want = append(want, libdns.Zone{Name: domain + "."})
	}

	// We only control a limited number of zones in the test account, there may be preexisting zones
	// that are unknown to us. Ignore all unknown zones.
	opts := cmp.Options{
		cmpopts.IgnoreSliceElements(func(zone libdns.Zone) bool {
			return !testDomains[strings.TrimSuffix(zone.Name, ".")]
		}),
		cmpopts.SortSlices(func(a, b libdns.Zone) int { return gocmp.Compare(a.Name, b.Name) }),
	}
	if diff := cmp.Diff(want, got, opts); diff != "" {
		t.Errorf("ListZones() unexpected diff [-want +got]: %s", diff)
	}
}

func TestProvider(t *testing.T) {
	if *token == "" || *domain == "" {
		t.Skip("skipping integration test; both -token and -domain must be set")
	}

	createDomain(t, *domain)

	p := &desec.Provider{
		Token: *token,
	}
	suite := libdnstest.NewTestSuite(p, *domain+".")
	suite.RunTests(t)
}
