package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/hashicorp/consul/api"
	"github.com/kolide/osquery-go/plugin/table"
	log "github.com/sirupsen/logrus"
)

func flat(m map[string]string) string {
	x := []string{}
	for k, v := range m {
		x = append(x, fmt.Sprintf("%v=%v", k, v))
	}
	return strings.Join(x, ",")

}

func ConsulLocalChecks() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("Node"),
		table.TextColumn("CheckID"),
		table.TextColumn("Name"),
		table.TextColumn("Status"),
		table.TextColumn("Notes"),
		table.TextColumn("Output"),
		table.TextColumn("ServiceID"),
		table.TextColumn("ServiceName"),
		table.TextColumn("HTTP"),
		table.TextColumn("Header"),
		table.TextColumn("Method"),
		table.TextColumn("TLSSkipVerify"),
		table.TextColumn("TCP"),
		table.TextColumn("Interval"),
		table.TextColumn("Timeout"),
		table.TextColumn("DeregisterCriticalServiceAfter"),
	}
}

func HandleConsulLocalChecks(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	results := []map[string]string{}
	client, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		return results, err
	}
	c, err := client.Agent().Checks()
	if err != nil {
		return results, err
	}
	log.Debugf("Checks found: %d", len(c))
	for _, check := range c {
		x := map[string]string{}
		x["CheckID"] = check.CheckID
		x["Name"] = check.Name
		x["Status"] = check.Status
		x["Notes"] = check.Notes
		x["Output"] = check.Output
		x["ServiceID"] = check.ServiceID
		x["ServiceName"] = check.ServiceName
		x["HTTP"] = check.Definition.HTTP
		x["Header"] = fmt.Sprintf("%v", check.Definition.Header)
		x["Method"] = check.Definition.Method
		x["TLSSkipVerify"] = strconv.FormatBool(check.Definition.TLSSkipVerify)
		x["TCP"] = check.Definition.TCP
		x["Interval"] = check.Definition.Interval.String()
		x["Timeout"] = check.Definition.Timeout.String()
		x["DeregisterCriticalServiceAfter"] = check.Definition.DeregisterCriticalServiceAfter.String()
		results = append(results, x)
	}
	return results, nil
}

func ConsulAgentMembers() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("Name"),
		table.TextColumn("Addr"),
		table.TextColumn("Tags"),
		table.IntegerColumn("Port"),
		table.IntegerColumn("Status"),
		table.IntegerColumn("ProtocolMin"),
		table.IntegerColumn("ProtocolMax"),
		table.IntegerColumn("ProtocolCur"),
		table.IntegerColumn("DelegateMin"),
		table.IntegerColumn("DelegateMax"),
		table.IntegerColumn("DelegateCur"),
	}
}

func HandleConsulAgentMembers(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	results := []map[string]string{}
	client, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		return results, err
	}
	m, err := client.Agent().Members(false)
	if err != nil {
		return results, err
	}
	log.Debugf("Members found: %d", len(m))
	for _, member := range m {
		x := map[string]string{}
		x["Name"] = member.Name
		x["Addr"] = member.Addr
		x["Tags"] = flat(member.Tags)
		x["Port"] = fmt.Sprintf("%v", member.Port)
		x["Status"] = fmt.Sprintf("%v", member.Status)
		x["ProtocolMin"] = fmt.Sprintf("%v", member.ProtocolMin)
		x["ProtocolMax"] = fmt.Sprintf("%v", member.ProtocolMax)
		x["ProtocolCur"] = fmt.Sprintf("%v", member.ProtocolCur)
		x["DelegateMin"] = fmt.Sprintf("%v", member.DelegateMin)
		x["DelegateMax"] = fmt.Sprintf("%v", member.DelegateMax)
		x["DelegateCur"] = fmt.Sprintf("%v", member.DelegateCur)
		results = append(results, x)

	}
	return results, nil
}

func ConsulAgentServices() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("ID"),
		table.TextColumn("Service"),
		table.TextColumn("Tags"),
		table.TextColumn("Address"),
		table.IntegerColumn("Port"),
		table.IntegerColumn("EnableTagOverride"),
		table.IntegerColumn("CreateIndex"),
		table.IntegerColumn("ModifyIndex"),
	}
}

func HandleConsulAgentServices(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	results := []map[string]string{}
	client, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		return results, err
	}
	s, err := client.Agent().Services()
	if err != nil {
		return results, err
	}
	log.Debugf("Members found: %d", len(s))
	for _, member := range s {
		x := map[string]string{}
		x["ID"] = member.ID
		x["Service"] = member.Service
		x["Tags"] = strings.Join(member.Tags, ",")
		x["Address"] = member.Address
		x["Port"] = fmt.Sprintf("%v", member.Port)
		x["EnableTagOverride"] = fmt.Sprintf("%v", member.EnableTagOverride)
		x["CreateIndex"] = fmt.Sprintf("%v", member.CreateIndex)
		x["ModifyIndex"] = fmt.Sprintf("%v", member.ModifyIndex)
		results = append(results, x)

	}
	return results, nil
}

func ConsulCatalogDatacenter() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("Datacenter"),
	}
}

func HandleConsulCatalogDatacenter(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	results := []map[string]string{}
	client, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		return results, err
	}
	s, err := client.Catalog().Datacenters()
	if err != nil {
		return results, err
	}
	log.Debugf("Members found: %d", len(s))
	for _, member := range s {
		x := map[string]string{}
		x["Datacenter"] = member
		results = append(results, x)

	}
	return results, nil
}

func ConsulStatusLeader() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("Leader"),
	}
}

func HandleConsulStatusLeader(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	results := []map[string]string{}
	client, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		return results, err
	}
	s, err := client.Status().Leader()
	if err != nil {
		return results, err
	}
	x := map[string]string{}
	x["Leader"] = s
	results = append(results, x)
	return results, nil
}
func ConsulStatusPeers() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("peer"),
	}
}

func HandleConsulStatusPeers(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	results := []map[string]string{}
	client, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		return results, err
	}
	s, err := client.Status().Peers()
	if err != nil {
		return results, err
	}
	log.Debugf("Members found: %d", len(s))
	for _, member := range s {
		x := map[string]string{}
		x["peer"] = member
		results = append(results, x)

	}
	return results, nil
}

func init() {
	Plugins["consul_agent_checks"] = table.NewPlugin("consul_agent_checks", ConsulLocalChecks(), HandleConsulLocalChecks)
	Plugins["consul_agent_members"] = table.NewPlugin("consul_agent_members", ConsulAgentMembers(), HandleConsulAgentMembers)
	Plugins["consul_agent_services"] = table.NewPlugin("consul_agent_services", ConsulAgentServices(), HandleConsulAgentServices)
	Plugins["consul_catalog_datacenter"] = table.NewPlugin("consul_catalog_datacenter", ConsulCatalogDatacenter(), HandleConsulCatalogDatacenter)
	Plugins["consul_status_leader"] = table.NewPlugin("consul_status_leader", ConsulStatusLeader(), HandleConsulStatusLeader)
	Plugins["consul_status_peers"] = table.NewPlugin("consul_status_peers", ConsulStatusPeers(), HandleConsulStatusPeers)
}
