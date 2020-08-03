package kaspersky_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/pixfid/go-ksc/kaspersky"
)

func expectSucceeded(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

func expectEqual(t *testing.T, expected interface{}, actual interface{}) {
	if !reflect.DeepEqual(expected, actual) {
		t.Fatalf("\n expected: \n %v \n actual: \n %v", expected, actual)
	}
}

func TestHostGroupGetDomains(t *testing.T) {
	handleFunc := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		response := `{
			"PxgRetVal": [
			  {
				"type": "params",
				"value": {
				  "KLHST_WKS_WINDOMAIN": "WORKGROUP",
				  "KLHST_WKS_WINDOMAIN_TYPE": 1
				}
			  },
			  {
				"type": "params",
				"value": {
				  "KLHST_WKS_WINDOMAIN": "KL",
				  "KLHST_WKS_WINDOMAIN_TYPE": 0
				}
			  }
			]
		  }`
		w.Write([]byte(response))
	}
	handler := http.NewServeMux()
	handler.HandleFunc("/api/v1.0/HostGroup.GetDomains", handleFunc)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	ctx := context.Background()
	client := kaspersky.New(kaspersky.Config{Server: srv.URL})
	actual, err := client.HostGroup.GetDomains(ctx)
	expectSucceeded(t, err)

	expected := []kaspersky.DomainParams{
		kaspersky.DomainParams{
			kaspersky.Domain{
				Name: "WORKGROUP",
				Type: kaspersky.WindowsWorkGroup,
			},
		},
		kaspersky.DomainParams{
			kaspersky.Domain{
				Name: "KL",
				Type: kaspersky.WindowsNTDomain,
			},
		},
	}
	expectEqual(t, expected, actual)
}
