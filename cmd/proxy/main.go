package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/gob"
	"flag"
	"github.com/elazarl/goproxy"
	"github.com/nim4/cyrus/core/cache"
	"github.com/nim4/cyrus/core/models"
	"github.com/nim4/cyrus/core/mq"
	"github.com/nim4/cyrus/core/utils"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

func drainBody(r io.ReadCloser) (rc io.ReadCloser, b []byte, err error) {
	b, err = ioutil.ReadAll(r)
	if err != nil {
		return nil, nil, err
	}
	return ioutil.NopCloser(bytes.NewReader(b)), b, nil
}

//start proxy and capture request and response
func startProxy(addr string) error {

	if err := setCA(caCert, caKey); err != nil {
		return err
	}

	proxy := goproxy.NewProxyHttpServer()
	tr := http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DisableCompression: true,
		DisableKeepAlives:  true,
	}

	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
	proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {

		ctx.RoundTripper = goproxy.RoundTripperFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (resp *http.Response, err error) {
			var reqBytes []byte
			req.Body, reqBytes, err = drainBody(req.Body)
			if err != nil {
				log.Print("drainBody request body failed: ", err)
				return
			}

			start := time.Now()
			resp, err = tr.RoundTrip(req)
			if err != nil {
				return
			}
			took := time.Since(start)

			if len(models.Config.Scan.Scope) > 0 {
				inScope := false
				for _, scope := range models.Config.Scan.Scope {
					host := req.URL.Host
					if strings.Contains(host, ":") {
						host, _, err = net.SplitHostPort(host)
					}
					if err != nil {
						log.Print("Spliting host:port failed: ", err)
						return
					}
					if strings.HasSuffix(host, scope) {
						inScope = true
						break
					}
				}

				if !inScope {
					log.Println("Out of scope: ", req.URL.Host)
					return
				}
			}

			rec := models.NewRecord(
				models.Request{
					Method:  req.Method,
					URL:     req.URL,
					Proto:   req.Proto,
					Headers: req.Header,
					Content: reqBytes,
				},
				models.Response{
					Status:  resp.StatusCode,
					Proto:   resp.Proto,
					Headers: resp.Header,
					Took:    took,
				},
			)

			resp.Body, rec.Resp.Content, err = drainBody(resp.Body)
			if err != nil {
				log.Print("drainBody response body failed: ", err)
				return
			}

			log.Print(rec.LogString())

			err = mq.Publish(rec)
			if err != nil {
				log.Print("Publishing failed: ", err)
			}
			return
		})
		return req, nil
	})
	log.Printf("Starting proxy server on %q", addr)
	return http.ListenAndServe(addr, proxy)
}

var caCert = []byte(`-----BEGIN CERTIFICATE-----
MIIFNzCCAx+gAwIBAgIJAKO+kS3q+KdcMA0GCSqGSIb3DQEBCwUAMDIxCzAJBgNV
BAYTAlRSMRMwEQYDVQQIDApTb21lLVN0YXRlMQ4wDAYDVQQKDAVDeXJ1czAeFw0x
ODA0MjExODI0NDJaFw0yMTAxMTUxODI0NDJaMDIxCzAJBgNVBAYTAlRSMRMwEQYD
VQQIDApTb21lLVN0YXRlMQ4wDAYDVQQKDAVDeXJ1czCCAiIwDQYJKoZIhvcNAQEB
BQADggIPADCCAgoCggIBAM0plc6dKC0f2DnJ4Ix4G178P4QIVyrkD2Kqawt3kNPh
uP0VtQvcaiiqVZUKbcX9FZy2J1wucVNuLpKzoviBMk77L3HJohz9LcL5+PIC1vvG
iEhSp+a95c6ySoiq+4XaJRjOISQrDzzcVpDFWi5Zzh/y5/sCMmXIr4+De42Bm3v9
Wt2Xnwc2KI4yywQX5fdMeYVEmS5lnJWVYPzH+sH/PFfFIpiTW8UYQnQkv0pannIE
IvU5kTGSj60tJEwo3s5V0m/HfKPTmNFFbxcKdKbn3kyPFaoCG+4WfRQ1eyksRHVq
x3lvGrKbav0rZjQib1ShqP/XWJxFqk2Lbz5qO+Lj2OI2qGoxOGBpLcpcNxUL7fdc
sHZUWzrQZZ067rdoMN2jkYnnfopebYzJ5RSglfTX2RcSzPqga4wQC/AlOSIRtal3
F8TPaHi9xEhZ+98NDRk4bnA1IraVzIPBd9O6RfYk6i7V4LoLlgoWSb26ZiHSR25d
e69lDpAHGAlMhWfEsRVrcQM59QfVrebGOhioAlRFlfeMftlMCDWcR+F9NHD82mYO
AgNbjxmqOiiO4zdT9e1eu9AWW2/krbeCQeXtg/yPhv6mkvqKC/KZgp5FGd9+D81k
4s4uItIkVCC+0i0lauydgaIXbFv7WiJIMVZcmnVSUdUkpaNv8vkUM/0CYfRQ0aH7
AgMBAAGjUDBOMB0GA1UdDgQWBBRgyR7cBayLk6tdtWSLKlYL/TOd9TAfBgNVHSME
GDAWgBRgyR7cBayLk6tdtWSLKlYL/TOd9TAMBgNVHRMEBTADAQH/MA0GCSqGSIb3
DQEBCwUAA4ICAQAMc6mQiyhYGo5WMOWEKF9/YqbeKYOc+zirGi58yL+PWTeaEYIb
E76ivOGr18tMcMwD5KCnfR2UK8lfX9lwZbCwJEc2wzZ03c4DKXF40N9e/f12L4Zo
J1B6pPPR7PGNZPdfWhmwDUKliw4C77aW4BGX2LddTtY81qG4rnaktbHwlDv7Dfkp
ulOu01qs+X3nRpdbGwaa8H04/sO5yv2xwZ7RxWF2fh1t/5HYA54kQp3NFNOM2ygn
qnqbrzimCiP7HLMzh7NMNTejV55Gvzy4t9abHQc1mshxjbs6Vxx4EnKsPeNaES70
W21A8alQphlct7BEj5JLWd5VHfCIY+sGIhZgcj2rXVHhanjlI1TYlbcs2dncZwpB
HNtdMO37PmAXO82YaZrx7qwDUUepSYE1+dLcR163CyhZLqisxAlVglK09QFSMuY5
JTj2Pp0OVBl8AB/vQSf3lhR3AWaBo1w2vg/pDv7Cw2cr0qyZ5vBdwwmAtK/nu3WT
JusH07JqKk4Js8ac1U65apCl++u4eRFpDB2wnHrqZ8D1LBJXdsvY8leiLpaQt6z1
B+TBvI9TpjrSLdmU+yvfiXML8ueUFOn++ZLlYCdYA8XZjn1JAt28IoeAgeJvrzCd
fuoU+P/DmrbTagQDKZ/DJWV8YxEUz8vEMP4UMv6B2LZbIwxjDV22/vPGRQ==
-----END CERTIFICATE-----`)

var caKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----`)

func setCA(caCert, caKey []byte) error {
	goproxyCa, err := tls.X509KeyPair(caCert, caKey)
	if err != nil {
		return err
	}
	if goproxyCa.Leaf, err = x509.ParseCertificate(goproxyCa.Certificate[0]); err != nil {
		return err
	}
	goproxy.GoproxyCa = goproxyCa
	goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectAccept, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
	goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
	goproxy.HTTPMitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectHTTPMitm, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
	goproxy.RejectConnect = &goproxy.ConnectAction{Action: goproxy.ConnectReject, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
	return nil
}

func main() {

	configFile := flag.String("config", "config.yml", "Path of configuration file")
	flag.Parse()

	err := models.LoadConfig(*configFile)
	utils.FailOnError(err, "Reading config file failed")

	err = cache.Connect(models.Config.Redis.Addr, models.Config.Redis.Password)
	utils.FailOnError(err, "Connecting to redis failed")

	b := new(bytes.Buffer)
	err = gob.NewEncoder(b).Encode(models.Config)
	utils.FailOnError(err, "Encoding config failed")

	err = cache.Set("Config", b.Bytes())
	utils.FailOnError(err, "Sending configuration to Cache server failed")

	err = mq.Connect(true)
	utils.FailOnError(err, "Connecting to AMQP failed")

	log.Fatal(startProxy(models.Config.Proxy.Addr))
}
