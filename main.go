/*
Domanager reads a YAML file like:
```
domains:
	-
	-
```

and pulls the domains info and where they point to, all records for them, and then tries to see what they're SSL records are like.
*/
package main

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/ayjayt/ilog"
	"github.com/ayjayt/sslchk"
	"github.com/spf13/viper"
	// letsencrypt
)

var (
	errNotFound = errors.New("not found")
)

var defaultLogger ilog.LoggerInterface
var ips map[string]interface{}
var domains map[string]interface{}

func init() {
	defaultLogger = &ilog.ZapWrap{Sugar: false}
	defaultLogger.Init()
	//defaultLogger.Info("Logging test")
	var err error
	viper.SetConfigName("domains")
	viper.AddConfigPath("/etc/domanager")
	viper.AddConfigPath("$HOME/")
	viper.AddConfigPath(".")
	err = viper.ReadInConfig()
	if err != nil {
		panic(err)
	}
}

// The info struct is what we build that contains information about the domain
type Info struct {
	domain        string
	name          string
	ip            string
	ipErr         error
	mail          string
	mailErr       error
	nameServer    string
	nameServerErr error
	get           bool
	getErr        error
	certs         map[string]sslchk.CheckReturn
	certErr       error
}

func (i *Info) Out() {
	w := tabwriter.NewWriter(os.Stdout, 28, 1, 1, '.', tabwriter.Debug)
	if i.ipErr == nil {
		fmt.Fprint(w, i.domain+"\t"+i.name+"\t"+i.ip+"\t"+"irrelevant")
	} else {
		if i.nameServerErr == nil {
			fmt.Fprint(w, i.domain+"\tunknown\t"+i.ip+"\t"+i.nameServer)
		} else {
			fmt.Fprint(w, i.domain+"\tunknown\t"+i.ip+"\tunkown")

		}
	}
	if i.mailErr == nil {
		fmt.Fprint(w, "\tGOOGLE-MAIL")
	} else {
		fmt.Fprint(w, "\tNO MAIL")
	}
	if i.get {
		fmt.Fprint(w, "\tRESPONDING")
	} else {
		fmt.Fprint(w, "\tUNRESPONSIVE")
	}
	if i.certErr != nil {
		maxLen := 15
		if len(i.certErr.Error()) < 15 {
			maxLen = len(i.certErr.Error())
		}
		fmt.Fprintln(w, "\t"+i.certErr.Error()[:maxLen]+"\t")
	} else {
		fmt.Fprintln(w, "\tOK\t")
	}
	w.Flush()
}

func main() {
	domains = viper.GetStringMap("domains")
	ips = viper.GetStringMap("ips")
	chn := make(chan *Info, len(domains))
	for domain, _ := range domains {
		go func(domain string) {
			c := new(http.Client)
			c.Timeout = time.Millisecond * 1000

			me := new(Info)
			me.domain = domain
			retreivedIPs, err := net.LookupIP(domain)
			if err != nil {
				me.ipErr = err
			} else {
				me.ipErr = errNotFound
				for _, ip := range retreivedIPs {
					if ipMetaData, ok := ips[ip.String()]; ok {
						me.ip = ip.String()
						if name, ok := ipMetaData.(map[string]interface{})["name"]; ok {
							me.name = name.(string)
						} else {
							me.name = "Unknown"
						}
						me.ipErr = nil
						break
					}
				}
			}
			// TODO: Okay, we've got the IP's name or we don't know what it is.

			// We're not using this right now
			//txt, err := net.LookupTXT(k)
			//if err != nil {
			//	fmt.Printf("\terr: %v\n", err)
			//} else {
			//	fmt.Printf("\tTXT: %v\n", txt)
			//}

			mx, err := net.LookupMX(domain)
			if err != nil {
				me.mailErr = err
			} else {
				me.mailErr = errNotFound
				for i, v := range mx {
					if i == 0 && strings.ToLower(v.Host) == "aspmx.l.google.com." {
						me.mailErr = nil
						me.mail = "Google"
					}
				}
			}

			ns, err := net.LookupNS(domain)
			if err != nil {
				me.nameServerErr = err
			} else {
				me.nameServerErr = errNotFound
				for i, v := range ns {
					if i == 0 {
						me.nameServerErr = nil
						me.nameServer = v.Host
					}
				}
			}
			resp, err := c.Get("http://" + domain)
			if err != nil {
				me.getErr = err
			} else {
				resp.Body.Close()
				if resp.StatusCode == 200 {
					me.getErr = nil
					me.get = true
				}
			}
			if me.getErr == nil {
				me.certs, me.certErr = sslchk.CheckHost(domain)
			} else {
				me.certs = nil
				me.certErr = errors.New("No response")
			}
			chn <- me
		}(domain)
	}
	i := 0
	mine := make([]Info, len(domains))
	for me := range chn {
		mine[i] = *me
		i++
		me.Out()
		if i == len(domains) {
			break
		}
	}
	for _, me := range mine {
		if me.certErr == nil {
			for _, myCert := range me.certs {
				myCert.Out()
			}
		}
	}
}
