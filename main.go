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
	"fmt"
	"github.com/spf13/viper"
	"net"
	"net/http"
	"time"
	// letsencrypt
	// logging
)

const ()

func init() {
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
func main() {
	list := viper.GetStringSlice("domains")
	c := new(http.Client)
	c.Timeout = time.Millisecond * 500
	for i, v := range list {
		fmt.Printf("%+v, %+v:\n", i, v)

		ips, err := net.LookupIP(v)
		if err != nil {
			fmt.Printf("\terr: %v\n", err)
		} else {
			fmt.Printf("\tIP: %v\n", ips)
		}
		txt, err := net.LookupTXT(v)
		if err != nil {
			fmt.Printf("\terr: %v\n", err)
		} else {
			fmt.Printf("\tTXT: %v\n", txt)
		}
		mx, err := net.LookupMX(v)
		if err != nil {
			fmt.Printf("\terr: %v\n", err)
		} else {
			fmt.Printf("\tMX: ")
			for i, v := range mx {
				if i == 0 {
					fmt.Printf("%v, ", v.Host)
				}
			}
			fmt.Printf("\n")
		}
		ns, err := net.LookupNS(v)
		if err != nil {
			fmt.Printf("\terr: %v\n", err)
		} else {
			fmt.Printf("\tNS: ")
			for i, v := range ns {
				if i == 0 {
					fmt.Printf("%v", v.Host)
				}
			}
			fmt.Printf("\n")
		}
		fmt.Printf("\tGET: ")
		resp, err := c.Get("http://" + v)
		if err != nil {
			fmt.Printf("err: %v\n", err)
		} else {
			fmt.Printf("%v\n", resp.Status)
			resp.Body.Close()
		}

	}
	// read a configuration file for domains and keys
	// get their records
	// print out their pointing info
	// print out their expiry info
}
