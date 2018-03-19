package main

import (
	"os"

	"github.com/jessevdk/go-flags"
	"github.com/kolide/osquery-go"
	"github.com/kolide/osquery-go/plugin/table"
	log "github.com/sirupsen/logrus"
)

type Options struct {
	SocketPath string `long:"socketpath" short:"s" env:"SOCKETPATH" required:"true" default:"$HOME/.osquery/shell.em" description:"Path to osproxy plugin socket"`
	Logging    struct {
		Level string `long:"level" default:"warn" description:"Level of logging"`
	} `namespace:"logging" group:"Logging Options"`
	Tables struct {
		Disabled []string `long:"enabled" env:"TABLES_DISABLED" default:"" description:"Tables to be disabled"`
		Consul   struct {
			Address string `long:"address" env:"CONSUL_ADDRESS" default:"127.0.0.1:8500" description:"Address consul is listening on"`
			Token   string `long:"token" env:"CONSUL_TOKEN" description:"Token for accessing consul"`
		} `namespace:"consul" group:"Consul Table Options"`
	} `namespace:"tables" group:"Tables Options"`
}

var options Options
var parser = flags.NewParser(&options, flags.Default)
var Plugins = make(map[string]*table.Plugin)

func Run() int {

	server, err := osquery.NewExtensionManagerServer("haproxy", options.SocketPath)
	if err != nil {
		log.Fatalf("Error creating extension: %s\n", err)
	}

	for k, v := range Plugins {
		if !contains(options.Tables.Disabled, k) {
			log.Infof("  Enabling table: %s", k)
			server.RegisterPlugin(v)
		} else {
			log.Infof("-> Disabled table: %s", k)
		}
	}
	if err := server.Run(); err != nil {
		log.Fatalln(err)
	}
	return 0
}

func main() {
	log.SetOutput(os.Stdout)
	if _, err := parser.Parse(); err != nil {
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type == flags.ErrHelp {
			os.Exit(0)
		} else {
			log.WithFields(log.Fields{
				"err": err,
			}).Error("Parsing error")
			os.Exit(1)
		}
	}
	lvl, err := log.ParseLevel(options.Logging.Level)
	if err != nil {
		log.WithFields(log.Fields{
			"err": err,
		}).Error("Could not parse level string")
	}
	log.SetLevel(lvl)
	os.Exit(Run())
}
