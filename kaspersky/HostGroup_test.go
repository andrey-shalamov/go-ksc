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

func NewTestServer() (*httptest.Server, *http.ServeMux) {
	handler := http.NewServeMux()
	srv := httptest.NewServer(handler)
	return srv, handler
}

func TestHostGroup(t *testing.T) {
	srv, handler := NewTestServer()
	defer srv.Close()

	ctx := context.Background()
	client := kaspersky.New(kaspersky.Config{Server: srv.URL})

	t.Run("GetDomains", func(t *testing.T) { getDomains(t, ctx, handler, client) })
	t.Run("GetHostProducts", func(t *testing.T) { getHostProducts(t, ctx, handler, client) })
}

func HandlerFuncOk(response string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(response))
	}
}

func getDomains(t *testing.T, ctx context.Context, handler *http.ServeMux, client *kaspersky.Client) {
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
	handler.HandleFunc("/api/v1.0/HostGroup.GetDomains", HandlerFuncOk(response))

	actual, _, err := client.HostGroup.GetDomains(ctx)
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

func getHostProducts(t *testing.T, ctx context.Context, handler *http.ServeMux, client *kaspersky.Client) {
	response := `{
		"PxgRetVal": {
		  "KES": {
			"type": "params",
			"value": {
			  "11.0.0.0": {
				"type": "params",
				"value": {
				  "BaseDate": {
					"type": "datetime",
					"value": "2019-05-19T21:12:00Z"
				  },
				  "BaseRecords": 13255858,
				  "CustomName": "C:\\Program Files (x86)\\Kaspersky Lab\\Kaspersky Endpoint Security for Windows\\avpcon.dll",
				  "DataFolder": "C:\\ProgramData\\KasperskyLab\\adminkit\\products\\9A253204F7FADCBCC260DAF609E13D53",
				  "DisplayName": "Kaspersky Endpoint Security для Windows",
				  "FileName": "avpcon.dll",
				  "FilePath": "C:\\Program Files (x86)\\Kaspersky Lab\\Kaspersky Endpoint Security for Windows\\",
				  "InstallTime": {
					"type": "datetime",
					"value": "2020-05-28T07:22:14Z"
				  },
				  "ModuleType": 34,
				  "ProdVersion": "11.1.1.126"
				}
			  }
			}
		  }
		}
	  }
	`
	handler.HandleFunc("/api/v1.0/HostGroup.GetHostProducts", HandlerFuncOk(response))

	actual, _, err := client.HostGroup.GetHostProducts(ctx, "host")
	expectSucceeded(t, err)

	expected := kaspersky.HostProductInfo{
		Name:        "KES",
		Version:     "11.0.0.0",
		ProdVersion: "11.1.1.126",
		BaseDate: kaspersky.DateTimeParams{
			Value: "2019-05-19T21:12:00Z",
		},
		CustomName:  "C:\\Program Files (x86)\\Kaspersky Lab\\Kaspersky Endpoint Security for Windows\\avpcon.dll",
		DisplayName: "Kaspersky Endpoint Security для Windows",
		FileName:    "avpcon.dll",
	}
	if len(actual) != 1 {
		t.Fatal("Expected one element array")
	}
	expectEqual(t, expected.Name, actual[0].Name)
	expectEqual(t, expected.Version, actual[0].Version)
	expectEqual(t, expected.ProdVersion, actual[0].ProdVersion)
	expectEqual(t, expected.FileName, actual[0].FileName)
	expectEqual(t, expected.CustomName, actual[0].CustomName)
	expectEqual(t, expected.DisplayName, actual[0].DisplayName)
	expectEqual(t, expected.BaseDate, actual[0].BaseDate)
}
