package mw

import (
	"encoding/xml"
	"testing"
)

func parseConnector(t *testing.T, serverXML string) tcConnector {
	t.Helper()
	var srv tcServer
	if err := xml.Unmarshal([]byte(serverXML), &srv); err != nil {
		t.Fatal(err)
	}
	if len(srv.Services) != 1 || len(srv.Services[0].Connectors) != 1 {
		t.Fatalf("夹具结构不符：%+v", srv)
	}
	return srv.Services[0].Connectors[0]
}

func TestEffectiveSSLProtocol(t *testing.T) {
	cases := []struct {
		name string
		xml  string
		want string
	}{
		{
			name: "SSLHostConfig 主流写法",
			xml: `<Server><Service><Connector port="8443" SSLEnabled="true">
					<SSLHostConfig protocols="TLSv1.1,TLSv1.2"><Certificate certificateKeystoreFile="x"/></SSLHostConfig>
				  </Connector></Service></Server>`,
			want: "TLSv1.1,TLSv1.2",
		},
		{
			name: "SSLHostConfig 优先于连接器属性",
			xml: `<Server><Service><Connector port="8443" SSLEnabled="true" sslProtocol="TLSv1.2">
					<SSLHostConfig protocols="TLSv1.2,TLSv1.3"/>
				  </Connector></Service></Server>`,
			want: "TLSv1.2,TLSv1.3",
		},
		{
			name: "JSSE sslProtocol 小写",
			xml:  `<Server><Service><Connector port="8443" SSLEnabled="true" sslProtocol="TLSv1"/></Service></Server>`,
			want: "TLSv1",
		},
		{
			name: "APR SSLProtocol 旧写法回归",
			xml:  `<Server><Service><Connector port="8443" SSLEnabled="true" SSLProtocol="all"/></Service></Server>`,
			want: "all",
		},
		{
			name: "无协议配置为空（规则不臆测）",
			xml:  `<Server><Service><Connector port="8443" SSLEnabled="true"><SSLHostConfig><Certificate certificateKeystoreFile="x"/></SSLHostConfig></Connector></Service></Server>`,
			want: "",
		},
	}
	for _, tc := range cases {
		if got := effectiveSSLProtocol(parseConnector(t, tc.xml)); got != tc.want {
			t.Errorf("%s：got %q want %q", tc.name, got, tc.want)
		}
	}
}
