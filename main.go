package main

import (
	"errors"
	"os"
	"regexp"

	"github.com/jessevdk/go-flags"
	"github.com/kolide/osquery-go"
	"github.com/kolide/osquery-go/plugin/table"
	log "github.com/sirupsen/logrus"
)

// embed regexp.Regexp in a new type so we can extend it
type myRegexp struct {
	*regexp.Regexp
}

// add a new method to our new regular expression type
func (r *myRegexp) FindStringSubmatchMap(s string) map[string]string {
	captures := make(map[string]string)

	match := r.FindStringSubmatch(s)
	if match == nil {
		return captures
	}

	for i, name := range r.SubexpNames() {
		// Ignore the whole regexp match and unnamed groups
		if i == 0 || name == "" {
			continue
		}

		captures[name] = match[i]

	}
	return captures
}

func ListAddresses(queryContext table.QueryContext) ([]string, error) {
	results := []string{}
	if addrList, ok := queryContext.Constraints["addr"]; ok {
		for _, a := range addrList.Constraints {
			results = append(results, a.Expression)
		}
		return results, nil
	}
	return results, errors.New("Constraints does not have addr")
}

// thread_id: 0
// date_now: 1521155474.723564
// loops: 1159
// wake_cache: 487
// wake_tasks: 163
// wake_applets: 3
// wake_signal: 0
// poll_exp: 653
// poll_drop: 157
// poll_dead: 0
// poll_skip: 0
// fd_skip: 0
// fd_lock: 0
// fd_del: 4
// conn_dead: 0
// stream: 10
// empty_rq: 841
// long_rq: 0

type Options struct {
	SocketPath string `long:"socketpath" short:"s" env:"SOCKETPATH" required:"truy" default:"$HOME/.osquery/shell.em" description:"Path to osproxy plugin socket"`
	Logging    struct {
		Level string `long:"level" default:"warn" description:"Level of logging"`
	} `namespace:"logging" group:"Logging Options"`
	Tables struct {
		Disabled []string `long:"enabled" env:"TABLES_DISABLED" default:"" description:"Tables to be disabled"`
	} `namespace:"tables" group:"Tables Options"`
}

var options Options
var parser = flags.NewParser(&options, flags.Default)

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func Run() int {
	plugins := map[string]*table.Plugin{
		"haproxy_sessions": table.NewPlugin("haproxy_sessions", SessionsColumns(), SessionsGenerate),
		"haproxy_activity": table.NewPlugin("haproxy_activity", ActivityColumns(), KVGenerate("show activity")),
		"haproxy_info":     table.NewPlugin("haproxy_info", InfoColumns(), KVGenerate("show info")),
	}

	server, err := osquery.NewExtensionManagerServer("haproxy", options.SocketPath)
	if err != nil {
		log.Fatalf("Error creating extension: %s\n", err)
	}

	for k, v := range plugins {
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
