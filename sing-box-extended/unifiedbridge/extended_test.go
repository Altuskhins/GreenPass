//go:build with_naive_outbound && with_masque && with_sudoku

package unifiedbridge

import (
	"fmt"
	"testing"
)

func TestExtendedGreenPassConfigs(t *testing.T) {
	base := `{"log":{"disabled":true},"inbounds":[{"type":"mixed","listen":"127.0.0.1","listen_port":0}],"outbounds":[%s],"route":{"final":"proxy"}}`
	cases := map[string]string{
		"xhttp": `{"type":"vless","tag":"proxy","server":"example.com","server_port":443,"uuid":"3179dce2-2ff9-413c-85b4-c1d53ed41668","tls":{"enabled":true,"server_name":"example.com"},"transport":{"type":"xhttp","mode":"stream-up","host":"example.com","path":"/x","x_padding_bytes":"100-1000"}}`,
		"kcp":   `{"type":"vless","tag":"proxy","server":"example.com","server_port":443,"uuid":"3179dce2-2ff9-413c-85b4-c1d53ed41668","transport":{"type":"mkcp","seed":"secret","header_type":"none"}}`,
		"mieru": `{"type":"mieru","tag":"proxy","server":"example.com","server_port":27017,"transport":"TCP","username":"alice","password":"secret","multiplexing":"MULTIPLEXING_LOW"}`,
		"naive": `{"type":"naive","tag":"proxy","server":"example.com","server_port":443,"username":"alice","password":"secret","tls":{"enabled":true,"server_name":"example.com"}}`,
	}
	for name, outbound := range cases {
		t.Run(name, func(t *testing.T) {
			if err := ValidateConfig(fmt.Sprintf(base, outbound)); err != nil {
				t.Fatalf("validate %s config: %v", name, err)
			}
		})
	}
}
