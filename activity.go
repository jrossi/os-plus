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

// Name: HAProxy
// Version: 1.8.4-1deb90d
// Release_date: 2018/02/08
// node: war-machines.local
// Uptime: 0d 0h54m34s
// Nbproc: 1
// Process_num: 1
// Pid: 55112
// Uptime_sec: 3274
// Memmax_MB: 0
// PoolAlloc_MB: 0
// PoolUsed_MB: 0
// PoolFailed: 0
// Ulimit-n: 8225
// Maxsock: 8225
// Maxconn: 4096
// Hard_maxconn: 4096
// CurrConns: 0
// CumConns: 32
// CumReq: 32
// MaxSslConns: 0
// CurrSslConns: 0
// CumSslConns: 0
// Maxpipes: 0
// PipesUsed: 0
// PipesFree: 0
// ConnRate: 0
// ConnRateLimit: 0
// MaxConnRate: 0
// SessRate: 0
// SessRateLimit: 0
// MaxSessRate: 0
// SslRate: 0
// SslRateLimit: 0
// MaxSslRate: 0
// SslFrontendKeyRate: 0
// SslFrontendMaxKeyRate: 0
// SslFrontendSessionReuse_pct: 0
// SslBackendKeyRate: 0
// SslBackendMaxKeyRate: 0
// SslCacheLookups: 0
// SslCacheMisses: 0
// CompressBpsIn: 0
// CompressBpsOut: 0
// CompressBpsRateLim: 0
// ZlibMemUsage: 0
// MaxZlibMemUsage: 0
// Tasks: 6
// Run_queue: 0
// Idle_pct: 100

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

func KVGenerate(cmd string) table.GenerateFunc {

	x := func(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {

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
	return x

}
