package cutover

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func promServer(t *testing.T, body map[string]string) (*Prom, *[]string) {
	t.Helper()
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		asked = append(asked, r.URL.Path+" "+q.Get("query")+" "+q.Get("time")+q.Get("start")+" "+q.Get("step"))
		b, ok := body[q.Get("query")]
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"status":"error","errorType":"bad_data","error":"parse error"}`))
			return
		}
		_, _ = w.Write([]byte(b))
	}))
	t.Cleanup(srv.Close)
	return &Prom{Base: srv.URL + "/"}, &asked
}

func TestPromDecodesVectorsScalarsAndMatrices(t *testing.T) {
	p, asked := promServer(t, map[string]string{
		"vec":    `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"rule_id":"a"},"value":[1793620800.5,"42"]}]}}`,
		"empty":  `{"status":"success","data":{"resultType":"vector","result":[]}}`,
		"scalar": `{"status":"success","data":{"resultType":"scalar","result":[1793620800,"7.5"]}}`,
		"mat":    `{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"engine":"v2"},"values":[[1793620800,"1"],[1793620801,"2"]]}]}}`,
	})
	ctx := context.Background()
	at := time.Unix(1793620800, 0)
	v, err := p.Query(ctx, "vec", at)
	if err != nil || len(v) != 1 || v[0].Value != 42 || v[0].Labels["rule_id"] != "a" {
		t.Fatalf("vector %+v, %v", v, err)
	}
	if v, err := p.Query(ctx, "empty", at); err != nil || len(v) != 0 {
		t.Fatalf("empty %+v, %v", v, err)
	}
	if v, err := p.Query(ctx, "scalar", at); err != nil || len(v) != 1 || v[0].Value != 7.5 {
		t.Fatalf("scalar %+v, %v", v, err)
	}
	m, err := p.QueryRange(ctx, "mat", at, at.Add(time.Second), time.Second)
	if err != nil || len(m) != 1 || len(m[0].Points) != 2 || m[0].Points[1].V != 2 || !m[0].Points[1].T.Equal(at.Add(time.Second)) {
		t.Fatalf("matrix %+v, %v", m, err)
	}
	if _, err := p.Query(ctx, "mat", at); err == nil {
		t.Fatal("a matrix from an instant query was accepted")
	}
	if _, err := p.Query(ctx, "nope", at); err == nil || !strings.Contains(err.Error(), "parse error") {
		t.Fatalf("error %v", err)
	}
	if !strings.HasPrefix((*asked)[0], "/api/v1/query vec 1793620800.000") || !strings.HasSuffix((*asked)[3], " 1") {
		t.Fatalf("requests %q", *asked)
	}
}

func TestPromDur(t *testing.T) {
	for d, want := range map[time.Duration]string{
		48 * time.Hour:          "48h",
		90 * time.Minute:        "90m",
		1500 * time.Millisecond: "2s",
	} {
		if got := promDur(d); got != want {
			t.Errorf("promDur(%s) = %s, want %s", d, got, want)
		}
	}
}
