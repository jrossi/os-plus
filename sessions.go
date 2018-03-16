package main

import (
	"bufio"
	"context"
	"errors"
	"log"
	"regexp"

	"github.com/bcicen/go-haproxy"
	"github.com/kolide/osquery-go/plugin/table"
)

// SessionColumns returns the columns that our table will return.
// Example:
// 0x7fc4ca6009f0: proto=unix_stream src=unix:1 fe=GLOBAL be=<NONE> srv=<none> ts=02 age=18s calls=1 rq[f=40c08202h,i=0,an=00h,rx=,wx=,ax=] rp[f=c0048202h,i=0,an=00h,rx=,wx=,ax=] s0=[7,ch,fd=7,ex=] s1=[7,4018h,fd=-1,ex=] exp=1m42s
// 0x7fc4ca7012d0: proto=tcpv4 src=127.0.0.1:49765 fe=psql be=psql srv=cockroach1 ts=08 age=8s calls=3 rq[f=40848202h,i=0,an=00h,rx=52s,wx=,ax=] rp[f=c0048202h,i=0,an=00h,rx=52s,wx=,ax=] s0=[7,8h,fd=8,ex=] s1=[7,18h,fd=9,ex=] exp=2s
func SessionColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("addr"),
		table.TextColumn("id"),
		table.TextColumn("proto"),
		table.TextColumn("src"),
		table.TextColumn("fe"),
		table.TextColumn("be"),
		table.TextColumn("srv"),
		table.TextColumn("ts"),
		table.TextColumn("age"),
		table.IntegerColumn("calls"),
		table.TextColumn("rq_f"),
		table.TextColumn("rq_i"),
		table.TextColumn("rq_an"),
		table.TextColumn("rq_rx"),
		table.TextColumn("rq_wx"),
		table.TextColumn("rq_ax"),
		table.TextColumn("rp_f"),
		table.TextColumn("rp_i"),
		table.TextColumn("rp_an"),
		table.TextColumn("rp_rx"),
		table.TextColumn("rp_wx"),
		table.TextColumn("rp_ax"),
		table.IntegerColumn("exp"),
	}
}

// SessionsGenerate will be called whenever the table is queried. It should return
// a full table scan.
func SessionsGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	SessionRE := myRegexp{regexp.MustCompile(`(?P<id>\w+): proto=(?P<proto>\S+) src=(?P<src>\S+) fe=(?P<fe>\S+) be=(?P<be>\S+) srv=(?P<srv>\S+) ts=(?P<ts>\S+) age=(?P<age>\S+) calls=(?P<calls>\S+) rq\[f=(?P<rq_f>[^,]+),i=(?P<rq_i>[^,]*),an=(?P<rq_an>[^,]*),rx=(?P<rq_rx>[^,]*),wx=(?P<rq_wx>[^,]*),ax=(?P<rq_ax>[^\]]*)] rp\[f=(?P<rp_f>[^,]+),i=(?P<rp_I>[^,]*),an=(?P<rp_an>[^,]*),rx=(?P<rp_rx>[^,]*),wx=(?P<rp_wx>[^,]*),ax=(?P<rp_ax>[^\]]*)] .*exp=(?P<exp>\S*)`)}

	results := []map[string]string{}

	addrList, err := ListAddresses(queryContext)
	if err != nil {
		log.Println("ListAddresses return error: ", err)
		return results, err
	}
	for _, a := range addrList {
		client := &haproxy.HAProxyClient{Addr: a}
		data, err := client.RunCommand("show sess")
		if err != nil {
			log.Println("Haproxy Client RunCommand error show sess: ", err)
			return results, err
		}
		scanner := bufio.NewScanner(data)
		for scanner.Scan() {
			aline := scanner.Text()
			if aline != "" {
				m := SessionRE.FindStringSubmatchMap(aline)
				m["addr"] = a

				results = append(results, m)
			}
		}
		return results, nil
	}
	return results, errors.New("addr is required in WHERE to identify which sock to speak with")
}
