/*
Domanager reads a YAML file like:
```
domains:
	- username:password
	- username:password
```

and logs into name cheap, pulls the domains and where they point to, all records for them, and then tries to see what they're SSL records are like.
*/
package main

import (
	"fmt"

	"github.com/spf13/viper"
	// configuration
	// namecheap
	// letsencrypt
	// logging
)

func init() {
	viper.SetConfigName("domains")
	viper.AddConfigPath("/etc/domanager")
	viper.AddConfigPath("$HOME/")
	viper.AddConfigPath(".")
	err := viper.ReadInConfig()
	if err != nil {
		panic(err)
	}
}
func main() {
	list := viper.AllSettings()
	for i, v := range list {
		fmt.Printf("%+v, %+v\n", i, v)
	}
	// read a configuration file for domains and keys
	// get their records
	// print out their pointing info
	// print out their expiry info
}
