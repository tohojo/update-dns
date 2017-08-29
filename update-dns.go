// Author:   Toke Høiland-Jørgensen (toke@toke.dk)
// Date:     8 May 2017
// Copyright (c) 2017, Toke Høiland-Jørgensen
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

func readConfig() string {
	flag := pflag.FlagSet{}

	flag.BoolP("delete", "d", false, "Delete name")
	viper.BindPFlag("delete", flag.Lookup("delete"))

	flag.BoolP("add", "a", false, "Add name")
	viper.BindPFlag("add", flag.Lookup("add"))

	flag.StringP("server", "s", "", "Server name")
	viper.BindPFlag("server", flag.Lookup("server"))

	flag.StringP("zone", "z", "", "Zone to update (will be auto-detected if absent)")
	viper.BindPFlag("zone", flag.Lookup("zone"))

	viper.SetDefault("debug", false)

	viper.SetConfigName("update-dns")
	viper.AddConfigPath("$HOME/.update-dns")
	if err := viper.ReadInConfig(); err != nil {
		log.Panicf("Fatal error reading config file: %s \n", err)
	}

	flag.Parse(os.Args[1:])

	if len(viper.GetString("server")) == 0 {
		log.Panic("Missing server name")
	}

	if len(viper.GetString("tsig-secret")) == 0 {
		log.Panic("Missing tsig-secret")
	}

	if len(viper.GetString("tsig-name")) == 0 {
		log.Panic("Missing tsig-name")
	}

	if len(flag.Args()) == 0 || len(flag.Args()[0]) == 0 {
		log.Panic("Missing record name")
	}

	return strings.Join(flag.Args(), " ")
}

func getZone(name string) string {
	if len(viper.GetString("zone")) > 0 {
		return dns.Fqdn(viper.GetString("zone"))
	}

	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetEdns0(4096, true)
	m.SetQuestion(dns.Fqdn(name), dns.TypeSOA)

	r, _, err := c.Exchange(m, viper.GetString("server"))
	if err != nil {
		log.Panicf("Unable to discover zone: %s", err)
	}

	for _, k := range r.Ns {
		if soa, ok := k.(*dns.SOA); ok {
			return soa.Hdr.Name
		}
	}

	log.Panic("Couldn't find a zone")
	return ""
}

func update(rr dns.RR, zone string) error {
	c := new(dns.Client)
	c.TsigSecret = make(map[string]string)
	c.TsigSecret[viper.GetString("tsig-name")] = viper.GetString("tsig-secret")
	m := new(dns.Msg)
	m.SetUpdate(zone)

	if !viper.GetBool("add") {
		m.RemoveRRset([]dns.RR{rr})
	}

	if !viper.GetBool("delete") {
		m.Insert([]dns.RR{rr})
	}

	m.SetTsig(viper.GetString("tsig-name"), dns.HmacSHA256, 300, time.Now().Unix())

	log.Printf("Sending update:\n%s", m)

	r, _, err := c.Exchange(m, viper.GetString("server"))
	if err != nil {
		return err
	} else if r.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("Server refused registration. Code: %s",
			dns.RcodeToString[r.Rcode])
	}
	return nil
}

func main() {

	exitcode := 0

	defer func() {
		if !viper.GetBool("debug") {
			r := recover() // suppress stack traces
			if r != nil {
				exitcode = 2
			}
		}
		os.Exit(exitcode)
	}()

	record := readConfig()
	name := strings.SplitN(record, " ", 2)[0]
	zone := getZone(name)

	log.Printf("Got zone: %s", zone)

	rr, err := dns.NewRR(record)
	if err != nil {
		if viper.GetBool("delete") {
			rr = &dns.ANY{Hdr: dns.RR_Header{Name: dns.Fqdn(name),
				Ttl:    0,
				Rrtype: dns.TypeANY,
				Class:  dns.ClassANY}}
		} else {
			log.Printf("Unable to parse record: %s", err)
			exitcode = 1
			return
		}
	}

	err = update(rr, zone)
	if err != nil {
		log.Printf("Unable to send update: %s", err)
		exitcode = 1
		return
	}

	log.Print("Update successful")

}
