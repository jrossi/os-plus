package main

import (
	"log"
	"os"
	"regexp"

	"github.com/kolide/osquery-go"
	"github.com/kolide/osquery-go/plugin/table"
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

func main() {
	if len(os.Args) != 2 {
		log.Fatalf(`Usage: %s SOCKET_PATH`, os.Args[0])
	}

	server, err := osquery.NewExtensionManagerServer("haproxy", os.Args[1])
	if err != nil {
		log.Fatalf("Error creating extension: %s\n", err)
	}

	server.RegisterPlugin(table.NewPlugin("haproxy_session", SessionColumns(), SessionsGenerate))
	//server.RegisterPlugin(table.NewPlugin("haproxy_activity", ActivityColumns(), ActivityGenerate))
	if err := server.Run(); err != nil {
		log.Fatalln(err)
	}
}
