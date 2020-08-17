package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sensu-community/sensu-plugin-sdk/sensu"
	corev2 "github.com/sensu/sensu-go/api/core/v2"
	k8scorev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Config represents the check plugin config.
type Config struct {
	sensu.PluginConfig
	External       bool
	Namespace      string
	Kubeconfig     string
	ObjectKind     string
	EventType      string
	Interval       uint32
	Handlers       []string
	LabelSelectors string
	StatusMap      string
	AgentAPIURL    string
}

type eventStatusMap map[string]uint32

var (
	plugin = Config{
		PluginConfig: sensu.PluginConfig{
			Name:     "sensu-kubernetes-events",
			Short:    "Sensu Kubernetes events check",
			Keyspace: "sensu.io/plugins/sensu-kubernetes-events/config",
		},
	}

	options = []*sensu.PluginConfigOption{
		{
			Path:      "namespace",
			Env:       "KUBERNETES_NAMESPACE",
			Argument:  "namespace",
			Shorthand: "n",
			Default:   "",
			Usage:     "Namespace to which to limit this check",
			Value:     &plugin.Namespace,
		},
		{
			Path:      "external",
			Env:       "",
			Argument:  "external",
			Shorthand: "e",
			Default:   false,
			Usage:     "Connect to cluster externally (using kubeconfig)",
			Value:     &plugin.External,
		},
		{
			Path:      "kubeconfig",
			Env:       "KUBERNETES_CONFIG",
			Argument:  "kubeconfig",
			Shorthand: "c",
			Default:   "",
			Usage:     "Path to the kubeconfig file (default $HOME/.kube/config)",
			Value:     &plugin.Kubeconfig,
		},
		{
			Path:      "object-kind",
			Env:       "KUBERNETES_OBJECT_KIND",
			Argument:  "object-kind",
			Shorthand: "k",
			Default:   "",
			Usage:     "Object kind to limit query to (Pod, Cluster, etc.)",
			Value:     &plugin.ObjectKind,
		},
		{
			Path:      "event-type",
			Env:       "KUBERNETES_EVENT_TYPE",
			Argument:  "event-type",
			Shorthand: "t",
			Default:   "!=Normal",
			Usage:     "Query for fieldSelector type (supports = and !=)",
			Value:     &plugin.EventType,
		},
		{
			Path:      "label-selectors",
			Env:       "KUBERNETES_LABEL_SELECTORS",
			Argument:  "label-selectors",
			Shorthand: "l",
			Default:   "",
			Usage:     "Query for labelSelectors (e.g. release=stable,environment=qa)",
			Value:     &plugin.LabelSelectors,
		},
		{
			Path:      "status-map",
			Env:       "KUBERNETES_STATUS_MAP",
			Argument:  "status-map",
			Shorthand: "s",
			Default:   `{"normal": 0, "warning": 1, "default": 3}`,
			Usage:     "Map Kubernetes event type to Sensu event status",
			Value:     &plugin.StatusMap,
		},
		{
			Path:      "agent-api-url",
			Env:       "KUBERNETES_AGENT_API_URL",
			Argument:  "agent-api-url",
			Shorthand: "a",
			Default:   "http://127.0.0.1:3031/events",
			Usage:     "The URL for the Agent API used to send events",
			Value:     &plugin.AgentAPIURL,
		},
	}
)

func main() {
	check := sensu.NewGoCheck(&plugin.PluginConfig, options, checkArgs, executeCheck, true)
	check.Execute()
}

func checkArgs(event *corev2.Event) (int, error) {
	if plugin.External {
		if len(plugin.Kubeconfig) == 0 {
			if home := homeDir(); home != "" {
				plugin.Kubeconfig = filepath.Join(home, ".kube", "config")
			}
		}
	}

	// check to make sure plugin.EventType starts with = or !=, if not, prepend =
	if len(plugin.EventType) > 0 && !strings.HasPrefix(plugin.EventType, "!=") && !strings.HasPrefix(plugin.EventType, "=") {
		plugin.EventType = fmt.Sprintf("=%s", plugin.EventType)
	}

	// Pick these up from the STDIN event
	plugin.Interval = event.Check.Interval
	plugin.Handlers = event.Check.Handlers

	if len(plugin.AgentAPIURL) == 0 {
		return sensu.CheckStateCritical, fmt.Errorf("--agent-api-url or env var KUBERNETES_AGENT_API_URL required")
	}

	return sensu.CheckStateOK, nil
}

func executeCheck(event *corev2.Event) (int, error) {

	var config *rest.Config
	var err error

	if plugin.External {
		config, err = clientcmd.BuildConfigFromFlags("", plugin.Kubeconfig)
		if err != nil {
			return sensu.CheckStateCritical, fmt.Errorf("Failed to get kubeconfig: %v", err)
		}
	} else {
		config, err = rest.InClusterConfig()
		if err != nil {
			return sensu.CheckStateCritical, fmt.Errorf("Failed to get in InClusterConfig: %v", err)
		}
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return sensu.CheckStateCritical, fmt.Errorf("Failed to get clientset: %v", err)
	}

	var fieldSelectors []string

	if len(plugin.EventType) > 0 {
		// The plugin.EventType should include its operator (=/!=) that's why the
		// the string is abutted to the type string below
		fieldSelectors = append(fieldSelectors, fmt.Sprintf("type%s", plugin.EventType))
	}

	if len(plugin.ObjectKind) > 0 {
		fieldSelectors = append(fieldSelectors, fmt.Sprintf("involvedObject.kind=%s", plugin.ObjectKind))
	}

	listOptions := metav1.ListOptions{}

	if len(fieldSelectors) > 0 {
		listOptions.FieldSelector = strings.Join(fieldSelectors, ",")
	}

	if len(plugin.LabelSelectors) > 0 {
		listOptions.LabelSelector = plugin.LabelSelectors
	}

	events, err := clientset.CoreV1().Events(plugin.Namespace).List(context.TODO(), listOptions)
	if err != nil {
		return sensu.CheckStateCritical, fmt.Errorf("Failed to get events: %v", err)
	}

	output := []string{}

	for _, item := range events.Items {
		if time.Since(item.FirstTimestamp.Time).Seconds() <= float64(plugin.Interval) {
			output = append(output, fmt.Sprintf("Event for %s %s in namespace %s, reason: %q, message: %q", item.InvolvedObject.Kind, item.ObjectMeta.Name, item.ObjectMeta.Namespace, item.Reason, item.Message))
			event, err := createSensuEvent(item)
			if err != nil {
				return sensu.CheckStateCritical, err
			}
			err = submitEventAgentAPI(event)
			if err != nil {
				return sensu.CheckStateCritical, err
			}
		}
	}

	fmt.Printf("There are %d event(s) in the cluster that match field %q and label %q\n", len(output), listOptions.FieldSelector, listOptions.LabelSelector)
	for _, out := range output {
		fmt.Println(out)
	}

	return sensu.CheckStateOK, nil
}

func homeDir() string {
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	return os.Getenv("USERPROFILE") // windows
}

func createSensuEvent(k8sEvent k8scorev1.Event) (*corev2.Event, error) {
	event := &corev2.Event{}
	event.Check = &corev2.Check{}
	msg := strings.Fields(k8sEvent.Message)
	// If we have a definitive single word error mssage, use that as the check name
	if len(msg) == 2 && msg[0] == "Error:" {
		event.Check.ObjectMeta.Name = msg[1]
	} else {
		event.Check.ObjectMeta.Name = k8sEvent.ObjectMeta.Name
	}
	lowerKind := strings.ToLower(k8sEvent.InvolvedObject.Kind)
	lowerName := strings.ToLower(k8sEvent.InvolvedObject.Name)
	if lowerKind == "pod" {
		event.Check.ProxyEntityName = lowerName
	} else {
		event.Check.ProxyEntityName = fmt.Sprintf("%s-%s", lowerKind, lowerName)
	}
	status, err := getSensuEventStatus(k8sEvent.Type)
	if err != nil {
		return &corev2.Event{}, err
	}
	event.Check.Status = status
	event.Check.Interval = plugin.Interval
	event.Check.Handlers = plugin.Handlers
	event.Check.Output = fmt.Sprintf("Event for %s %s in namespace %s, reason: %q, message: %q\n", k8sEvent.InvolvedObject.Kind, k8sEvent.ObjectMeta.Name, k8sEvent.ObjectMeta.Namespace, k8sEvent.Reason, k8sEvent.Message)
	return event, nil
}

func submitEventAgentAPI(event *corev2.Event) error {

	encoded, _ := json.Marshal(event)
	resp, err := http.Post(plugin.AgentAPIURL, "application/json", bytes.NewBuffer(encoded))
	if err != nil {
		return fmt.Errorf("Failed to post event to %s failed: %v", plugin.AgentAPIURL, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("POST of event to %s failed with %v", plugin.AgentAPIURL, resp.Status)
	}

	return nil
}

func getSensuEventStatus(eventType string) (uint32, error) {
	statusMap := eventStatusMap{}
	err := json.Unmarshal([]byte(strings.ToLower(plugin.StatusMap)), &statusMap)
	if err != nil {
		return 255, err
	}
	// attempt to map it to a specified status, if not see if a
	// default status exists, otherwise return 255
	if val, ok := statusMap[strings.ToLower(eventType)]; ok {
		return val, nil
	} else if val, ok = statusMap["default"]; ok {
		return val, nil
	}
	return 255, nil
}
