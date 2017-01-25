package gcpce

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/net/context"
	"golang.org/x/oauth2/google"

	"google.golang.org/api/monitoring/v3"

	mp "github.com/mackerelio/go-mackerel-plugin-helper"
)

const zuluFormat string = "2006-01-02T15:4:05Z"
const duration string = "3m0s"
const computeDomain string = "compute.googleapis.com"

// ComputeEnginePlugin is mackerel plugin for Google Compute Engine
type ComputeEnginePlugin struct {
	Project           string
	InstanceName      string
	MonitoringService *monitoring.Service
	Option            *Option
}

// Option is optional argument to an API call
type Option struct {
	Key string
}

// Get returns key and value
func (c Option) Get() (string, string) {
	return "key", c.Key
}

var graphdef = map[string]mp.Graphs{
	"Firewall.DroppedBytesCount": mp.Graphs{
		Label: "FireWall Dropped Bytes Count",
		Unit:  "bytes",
		Metrics: []mp.Metrics{
			{Name: "dropped_bytes_count", Label: "Dropped Bytes Count", Type: "uint64"},
		},
	},
	"Firewall.DroppedPacketsCount": mp.Graphs{
		Label: "FireWall Dropped Packets Count",
		Unit:  "integer",
		Metrics: []mp.Metrics{
			{Name: "dropped_packets_count", Label: "Dropped Packets Count", Type: "uint64"},
		},
	},
	"Cpu.Utilization": mp.Graphs{
		Label: "CPU Utilization",
		Unit:  "percentage",
		Metrics: []mp.Metrics{
			{Name: "utilization", Label: "Utilization"},
		},
	},
	"Disk.BytesCount": mp.Graphs{
		Label: "Disk Read Bytes Count",
		Unit:  "bytes",
		Metrics: []mp.Metrics{
			{Name: "read_bytes_count", Label: "Read Bytes Count", Type: "uint64"},
			{Name: "write_bytes_count", Label: "Write Bytes Count", Type: "uint64"},
		},
	},
	"Disk.OpsCount": mp.Graphs{
		Label: "Disk Read Ops Count",
		Unit:  "integer",
		Metrics: []mp.Metrics{
			{Name: "read_ops_count", Label: "Read Ops Count", Type: "uint64"},
			{Name: "write_ops_count", Label: "Write Ops Count", Type: "uint64"},
		},
	},
	"Network.BytesCount": mp.Graphs{
		Label: "Network Received Bytes Count",
		Unit:  "bytes",
		Metrics: []mp.Metrics{
			{Name: "received_bytes_count", Label: "Received Bytes Count", Type: "uint64"},
			{Name: "sent_bytes_count", Label: "Sent Bytes Count", Type: "uint64"},
		},
	},
	"Network.PacketsCount": mp.Graphs{
		Label: "Network Received Packets Count",
		Unit:  "integer",
		Metrics: []mp.Metrics{
			{Name: "received_packets_count", Label: "Received Packets Count", Type: "uint64"},
			{Name: "sent_packets_count", Label: "Sent Packets Count", Type: "uint64"},
		},
	},
}

// GraphDefinition is return graphdef
func (p ComputeEnginePlugin) GraphDefinition() map[string]mp.Graphs {
	return graphdef
}

func getLatestValue(listCall *monitoring.ProjectsTimeSeriesListCall, filter string, startTime string, endTime string, opts *Option) (interface{}, error) {
	res, err := listCall.Filter(filter).IntervalEndTime(endTime).IntervalStartTime(startTime).Do(*opts)

	if err != nil || res == nil {
		return 0, err
	}

	valuePtr := res.TimeSeries[0].Points[0].Value

	if valuePtr.Int64Value != nil {
		return uint64(*valuePtr.Int64Value), nil
	} else if valuePtr.DoubleValue != nil {
		return *valuePtr.DoubleValue, nil
	} else {
		return 0, nil
	}

}

func mkFilter(domain string, metricName string, instance string) string {
	filter := `metric.type = "` + domain + metricName + `"`
	switch domain {
	case computeDomain:
		filter += " AND metric.label.instance_name = " + instance
	}

	return filter
}

// FetchMetrics fetches metrics from Google Monitoring API
func (p ComputeEnginePlugin) FetchMetrics() (map[string]interface{}, error) {
	now := time.Now()
	formattedEnd := now.Format(zuluFormat)
	m, _ := time.ParseDuration(duration)
	formattedStart := now.Add(-m).Format(zuluFormat)
	listCall := p.MonitoringService.Projects.TimeSeries.List(p.Project)

	stat := map[string]interface{}{}
	for _, metricName := range []string{
		"/firewall/dropped_bytes_count",
		"/firewall/dropped_packets_count",
		"/instance/cpu/utilization",
		"/instance/disk/read_bytes_count",
		"/instance/disk/read_ops_count",
		"/instance/disk/write_bytes_count",
		"/instance/disk/write_ops_count",
		"/instance/network/received_bytes_count",
		"/instance/network/received_packets_count",
		"/instance/network/sent_bytes_count",
		"/instance/network/sent_packets_count",
	} {
		value, err := getLatestValue(listCall, mkFilter(computeDomain, metricName, p.InstanceName), formattedStart, formattedEnd, p.Option)
		if err != nil {
			continue
		}
		splited := strings.Split(metricName, "/")
		stat[splited[len(splited)-1]] = value
	}

	return stat, nil
}

// Do the plugin
func Do() {
	optProject := flag.String("project", "", "Project No")
	optInstanceName := flag.String("instance-name", "", "Instance Name")
	optAPIKey := flag.String("api-key", "", "API key")
	flag.Parse()

	if *optProject == "" || *optInstanceName == "" || *optAPIKey == "" {
		fmt.Println("Errors:", errors.New("Not enough arguments"))
		return
	}

	ctx := context.Background()

	client, err := google.DefaultClient(ctx, monitoring.CloudPlatformScope)
	if err != nil {
		return
	}

	service, err := monitoring.New(client)
	if err != nil {
		return
	}

	var computeEngine = ComputeEnginePlugin{
		MonitoringService: service,
		Project:           "projects/" + *optProject,
		InstanceName:      *optInstanceName,
		Option:            &Option{Key: *optAPIKey},
	}

	helper := mp.NewMackerelPlugin(computeEngine)

	if os.Getenv("MACKEREL_AGENT_PLUGIN_META") != "" {
		helper.OutputDefinitions()
	} else {
		helper.OutputValues()
	}
}
