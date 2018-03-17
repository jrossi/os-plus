package main

import (
	"bufio"
	"context"
	"errors"
	"log"
	"strings"

	"github.com/bcicen/go-haproxy"
	"github.com/kolide/osquery-go/plugin/table"
)

func ActivityColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("addr"),
		table.TextColumn("date_now"),
		table.IntegerColumn("thread_id"),
		table.IntegerColumn("loops"),
		table.IntegerColumn("wake_cache"),
		table.IntegerColumn("wake_tasks"),
		table.IntegerColumn("wake_applets"),
		table.IntegerColumn("wake_signal"),
		table.IntegerColumn("poll_exp"),
		table.IntegerColumn("poll_drop"),
		table.IntegerColumn("poll_dead"),
		table.IntegerColumn("poll_skip"),
		table.IntegerColumn("fd_skip"),
		table.IntegerColumn("fd_lock"),
		table.IntegerColumn("fd_del"),
		table.IntegerColumn("conn_dead"),
		table.IntegerColumn("stream"),
		table.IntegerColumn("empty_rq"),
		table.IntegerColumn("long_rq"),
	}
}

func InfoColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("addr"),
		table.TextColumn("date_now"),
		table.TextColumn("Name"),
		table.TextColumn("Version"),
		table.TextColumn("Release_date"),
		table.TextColumn("node"),
		table.TextColumn("Uptime"),
		table.IntegerColumn("Nbproc"),
		table.IntegerColumn("Process_num"),
		table.IntegerColumn("Pid"),
		table.IntegerColumn("Uptime_sec"),
		table.IntegerColumn("Memmax_MB"),
		table.IntegerColumn("PoolAlloc_MB"),
		table.IntegerColumn("PoolUsed_MB"),
		table.IntegerColumn("PoolFailed"),
		table.IntegerColumn("Ulimit-n"),
		table.IntegerColumn("Maxsock"),
		table.IntegerColumn("Maxconn"),
		table.IntegerColumn("Hard_maxconn"),
		table.IntegerColumn("CurrConns"),
		table.IntegerColumn("CumConns"),
		table.IntegerColumn("CumReq"),
		table.IntegerColumn("MaxSslConns"),
		table.IntegerColumn("CurrSslConns"),
		table.IntegerColumn("CumSslConns"),
		table.IntegerColumn("Maxpipes"),
		table.IntegerColumn("PipesUsed"),
		table.IntegerColumn("PipesFree"),
		table.IntegerColumn("ConnRate"),
		table.IntegerColumn("ConnRateLimit"),
		table.IntegerColumn("MaxConnRate"),
		table.IntegerColumn("SessRate"),
		table.IntegerColumn("SessRateLimit"),
		table.IntegerColumn("MaxSessRate"),
		table.IntegerColumn("SslRate"),
		table.IntegerColumn("SslRateLimit"),
		table.IntegerColumn("MaxSslRate"),
		table.IntegerColumn("SslFrontendKeyRate"),
		table.IntegerColumn("SslFrontendMaxKeyRate"),
		table.IntegerColumn("SslFrontendSessionReuse_pct"),
		table.IntegerColumn("SslBackendKeyRate"),
		table.IntegerColumn("SslBackendMaxKeyRate"),
		table.IntegerColumn("SslCacheLookups"),
		table.IntegerColumn("SslCacheMisses"),
		table.IntegerColumn("CompressBpsIn"),
		table.IntegerColumn("CompressBpsOut"),
		table.IntegerColumn("CompressBpsRateLim"),
		table.IntegerColumn("ZlibMemUsage"),
		table.IntegerColumn("MaxZlibMemUsage"),
		table.IntegerColumn("Tasks"),
		table.IntegerColumn("Run_queue"),
		table.IntegerColumn("Idle_pct"),
	}
}

func init() {
	Plugins["haproxy_activity"] = table.NewPlugin("haproxy_activity", ActivityColumns(), KVGenerate("show activity"))
	Plugins["haproxy_info"] = table.NewPlugin("haproxy_info", InfoColumns(), KVGenerate("show info"))
}

func KVGenerate(cmd string) table.GenerateFunc {

	return func(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {

		results := []map[string]string{}

		addrList, err := ListAddresses(queryContext)
		if err != nil {
			log.Println("ListAddresses return error: ", err)
			return results, err
		}
		for _, a := range addrList {
			client := &haproxy.HAProxyClient{Addr: a}
			data, err := client.RunCommand(cmd)
			if err != nil {
				log.Println("Haproxy Client RunCommand error ", err, " commmad ", cmd)
				return results, err
			}
			scanner := bufio.NewScanner(data)
			x := map[string]string{}
			x["addr"] = a
			for scanner.Scan() {
				aline := scanner.Text()
				if aline != "" {
					s := strings.Split(aline, ":")
					k := strings.TrimSpace(s[0])
					v := strings.TrimSpace(s[1])
					x[k] = v
				}
			}
			results = append(results, x)
			return results, nil
		}
		return results, errors.New("addr is required in WHERE to identify which sock to speak with")
	}

}
