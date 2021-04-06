package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sensu-community/sensu-plugin-sdk/sensu"
	corev2 "github.com/sensu/sensu-go/api/core/v2"
	"github.com/sensu/sensu-go/types"
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
	External                  bool
	LocalTest                 bool
	Namespace                 string
	Kubeconfig                string
	ObjectKind                string
	ExcludeByReason           string
	EventType                 string
	Interval                  uint32
	Handlers                  []string
	LabelSelectors            string
	StatusMap                 string
	AgentAPIURL               string
	AddClusterAnnotation      string
	SensuNamespace            string
	SensuProxyEntity          string
	SensuExtraLabel           string
	SensuExtraAnnotation      string
	SensuAutoClose            bool
	SensuAutoCloseLabel       string
	APIBackendPass            string
	APIBackendUser            string
	APIBackendKey             string
	APIBackendHost            string
	APIBackendPort            int
	Secure                    bool
	TrustedCAFile             string
	InsecureSkipVerify        bool
	GrafanaMutatorIntegration bool
	Protocol                  string
}

// Auth represents the authentication info
type Auth struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    int64  `json:"expires_at"`
}

type eventStatusMap map[string]uint32

var (
	tlsConfig tls.Config

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
			Path:      "exclude-by-reason",
			Env:       "KUBERNETES_EXCLUDE_BY_REASON",
			Argument:  "exclude-by-reason",
			Shorthand: "",
			Default:   "",
			Usage:     "Exclude events based on Reason. E. OperationCompleted,BackOff",
			Value:     &plugin.ExcludeByReason,
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
		{
			Path:      "add-cluster-annotation",
			Env:       "ADD_CLUSTER_ANNOTATION",
			Argument:  "add-cluster-annotation",
			Shorthand: "C",
			Default:   "",
			Usage:     "Cluster Annotation to be add to event to make it easier to identify, e. k8s-dev-cluster",
			Value:     &plugin.AddClusterAnnotation,
		},
		{
			Path:      "sensu-namespace",
			Env:       "SENSU_NAMESPACE",
			Argument:  "sensu-namespace",
			Shorthand: "N",
			Default:   "",
			Usage:     "Sensu Namespace configuration, e. development",
			Value:     &plugin.SensuNamespace,
		},
		{
			Path:      "sensu-proxy-entity",
			Env:       "SENSU_PROXY_ENTITY",
			Argument:  "sensu-proxy-entity",
			Shorthand: "E",
			Default:   "",
			Usage:     "Sensu Proxy Entity to overwrite event.check.proxy_entity_name",
			Value:     &plugin.SensuProxyEntity,
		},
		{
			Path:      "sensu-extra-label",
			Env:       "SENSU_EXTRA_LABEL",
			Argument:  "sensu-extra-label",
			Shorthand: "",
			Default:   "",
			Usage:     "Add Extra Sensu Check Label in alert send to Sensu Agent API. Format: labelName=labelValue Or for multiple values labelName=labelValue,ExtraLabel=ExtraValue",
			Value:     &plugin.SensuExtraLabel,
		},
		{
			Path:      "sensu-extra-annotation",
			Env:       "SENSU_EXTRA_ANNOTATION",
			Argument:  "sensu-extra-annotation",
			Shorthand: "",
			Default:   "",
			Usage:     "Add Extra Sensu Check Annotation in alert send to Sensu Agent API. Format: annotationName=annotationValue Or for multiples use comma: annotationName=annotationValue,extraTwo=extraValue",
			Value:     &plugin.SensuExtraAnnotation,
		},
		{
			Path:      "auto-close-sensu",
			Env:       "AUTO_CLOSE_SENSU",
			Argument:  "auto-close-sensu",
			Shorthand: "A",
			Default:   false,
			Usage:     "Configure it to Auto Close if event doesn't match any Alerts from Kubernetes Events. Please configure others api-backend-* options before enable this flag",
			Value:     &plugin.SensuAutoClose,
		},
		{
			Path:      "auto-close-sensu-label",
			Env:       "AUTO_CLOSE_SENSU_LABEL",
			Argument:  "auto-close-sensu-label",
			Shorthand: "",
			Default:   "",
			Usage:     "Configure it to Auto Close if event doesn't match any Alerts from Kubernetes Events and with these label. e. {\"cluster\":\"k8s-dev\"}",
			Value:     &plugin.SensuAutoCloseLabel,
		},
		{
			Path:      "api-backend-user",
			Env:       "SENSU_API_USER",
			Argument:  "api-backend-user",
			Shorthand: "u",
			Default:   "admin",
			Usage:     "Sensu Go Backend API User",
			Value:     &plugin.APIBackendUser,
		},
		{
			Path:      "api-backend-pass",
			Env:       "SENSU_API_PASSWORD",
			Argument:  "api-backend-pass",
			Shorthand: "P",
			Default:   "P@ssw0rd!",
			Usage:     "Sensu Go Backend API Password",
			Value:     &plugin.APIBackendPass,
		},
		{
			Path:      "api-backend-key",
			Env:       "SENSU_API_KEY",
			Argument:  "api-backend-key",
			Shorthand: "K",
			Default:   "",
			Usage:     "Sensu Go Backend API Key",
			Value:     &plugin.APIBackendKey,
		},
		{
			Path:      "api-backend-host",
			Env:       "",
			Argument:  "api-backend-host",
			Shorthand: "B",
			Default:   "127.0.0.1",
			Usage:     "Sensu Go Backend API Host (e.g. 'sensu-backend.example.com')",
			Value:     &plugin.APIBackendHost,
		},
		{
			Path:      "api-backend-port",
			Env:       "",
			Argument:  "api-backend-port",
			Shorthand: "p",
			Default:   8080,
			Usage:     "Sensu Go Backend API Port (e.g. 4242)",
			Value:     &plugin.APIBackendPort,
		},
		{
			Path:      "secure",
			Env:       "",
			Argument:  "secure",
			Shorthand: "S",
			Default:   false,
			Usage:     "Use TLS connection to API",
			Value:     &plugin.Secure,
		},
		{
			Path:      "insecure-skip-verify",
			Env:       "",
			Argument:  "insecure-skip-verify",
			Shorthand: "i",
			Default:   false,
			Usage:     "skip TLS certificate verification (not recommended!)",
			Value:     &plugin.InsecureSkipVerify,
		},
		{
			Path:      "trusted-ca-file",
			Env:       "",
			Argument:  "trusted-ca-file",
			Shorthand: "f",
			Default:   "",
			Usage:     "TLS CA certificate bundle in PEM format",
			Value:     &plugin.TrustedCAFile,
		},
		{
			Path:      "grafana-mutator-integration",
			Env:       "",
			Argument:  "grafana-mutator-integration",
			Shorthand: "",
			Default:   false,
			Usage:     "Add extra check labels into sensu event for sensu-grafana-mutator integration",
			Value:     &plugin.GrafanaMutatorIntegration,
		},
	}
)

func main() {
	check := sensu.NewGoCheck(&plugin.PluginConfig, options, checkArgs, executeCheck, true)
	check.Execute()
}

func checkArgs(event *types.Event) (int, error) {
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
	plugin.SensuNamespace = event.Check.ObjectMeta.Namespace

	if len(plugin.Namespace) == 0 {
		plugin.Namespace = event.Check.Namespace
	} else if plugin.Namespace == "all" {
		plugin.Namespace = ""
	}

	// For Sensu Backend Connections
	if plugin.Secure {
		plugin.Protocol = "https"
	} else {
		plugin.Protocol = "http"
	}
	if len(plugin.TrustedCAFile) > 0 {
		caCertPool, err := corev2.LoadCACerts(plugin.TrustedCAFile)
		if err != nil {
			return sensu.CheckStateWarning, fmt.Errorf("Error loading specified CA file")
		}
		tlsConfig.RootCAs = caCertPool
	}
	tlsConfig.InsecureSkipVerify = plugin.InsecureSkipVerify

	// tlsConfig.BuildNameToCertificate()
	tlsConfig.CipherSuites = corev2.DefaultCipherSuites

	if len(plugin.AgentAPIURL) == 0 {
		return sensu.CheckStateCritical, fmt.Errorf("--agent-api-url or env var KUBERNETES_AGENT_API_URL required")
	}

	// check if format is correct
	if plugin.SensuExtraLabel != "" {
		if !strings.Contains(plugin.SensuExtraLabel, "=") {
			return sensu.CheckStateWarning, fmt.Errorf("Please use Format: Label=Value. Wrong format --sensu-extra-label %s", plugin.SensuExtraLabel)
		}
	}
	if plugin.SensuExtraAnnotation != "" {
		if !strings.Contains(plugin.SensuExtraAnnotation, "=") {
			return sensu.CheckStateWarning, fmt.Errorf("Please use Format: Annotation=Value. Wrong format --sensu-extra-annotation %s", plugin.SensuExtraAnnotation)
		}
	}

	return sensu.CheckStateOK, nil
}

func executeCheck(event *types.Event) (int, error) {

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
	excludeReasons := []string{}
	excludeList := false
	if plugin.ExcludeByReason != "" {
		excludeReasons = stringToSliceStrings(plugin.ExcludeByReason)
		excludeList = true
	}

	fmt.Printf("Number of kubernetes events found: %d \n", len(events.Items))

	for _, item := range events.Items {
		if excludeList && stringInSlice(item.Reason, excludeReasons) {
			continue
		}
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

	// Compare sensu events with alerts and resolved it
	if plugin.SensuAutoClose {
		var autherr error
		auth := Auth{}
		if len(plugin.APIBackendKey) == 0 {
			auth, autherr = authenticate()

			if autherr != nil {
				return sensu.CheckStateUnknown, autherr
			}
		}
		sensuEvents, err := getEvents(auth, plugin.SensuNamespace)
		if err != nil {
			return sensu.CheckStateCritical, err
		}
		fmt.Printf("Number of Sensu Events found: %d\n", len(sensuEvents))
		for _, e := range sensuEvents {
			for k, v := range e.Labels {
				if k == "io.kubernetes.event.id" {
					if !checkKubernetesEventID(events, v) {
						fmt.Printf("Closing %s\n", e.Check.Name)
						output := fmt.Sprintf("Resolved Automatically \n%s", e.Check.Output)
						e.Check.Output = output
						e.Check.Status = 0
						err = submitEventAgentAPI(e)
						if err != nil {
							return sensu.CheckStateCritical, err
						}
					}
				}
			}
		}
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
	msgFields := strings.Fields(k8sEvent.Message)

	lowerKind := strings.ToLower(k8sEvent.InvolvedObject.Kind)
	lowerName := strings.ToLower(k8sEvent.InvolvedObject.Name)
	lowerFieldPath := strings.ToLower(k8sEvent.InvolvedObject.FieldPath)
	lowerReason := strings.ToLower(k8sEvent.Reason)
	lowerMessage := strings.ToLower(k8sEvent.Message)
	// default command
	event.Check.Command = plugin.Name

	// Default labels
	event.ObjectMeta.Labels = make(map[string]string)
	event.ObjectMeta.Labels["io.kubernetes.event.id"] = k8sEvent.ObjectMeta.Name
	event.ObjectMeta.Labels["io.kubernetes.event.reason"] = k8sEvent.Reason
	event.ObjectMeta.Labels["io.kubernetes.event.namespace"] = k8sEvent.ObjectMeta.Namespace
	event.ObjectMeta.Labels[plugin.Name] = "owner"
	if plugin.AddClusterAnnotation != "" {
		event.ObjectMeta.Labels["io.kubernetes.cluster"] = plugin.AddClusterAnnotation
	}

	// Sensu Event Name
	switch lowerKind {
	case "pod":
		if strings.HasPrefix(lowerFieldPath, "spec.containers") {
			// This is a Pod/Container event (i.e. an event that is associated with a
			// K8s Pod resource, with reference to a specific container in the pod).
			// Pod/Container event names need to be prefixed with container names to
			// avoid event name collisions (e.g. container-influxdb-backoff vs
			// container-grafana-backoff).
			start := strings.Index(lowerFieldPath, "{") + 1
			end := strings.Index(lowerFieldPath, "}")
			container := lowerFieldPath[start:end]
			if len(msgFields) == 2 && msgFields[0] == "Error:" {
				// Expected output: container-<container_name>-<error>
				//
				// Example(s):
				// - container-nginx-imagepullbackoff
				event.Check.ObjectMeta.Name = fmt.Sprintf(
					"container-%s-%s",
					strings.ToLower(container),
					strings.ToLower(msgFields[1]),
				)
			} else {
				// Expected output: container-<container_name>-<reason>
				//
				// Example(s):
				// - container-nginx-started
				event.Check.ObjectMeta.Name = fmt.Sprintf(
					"container-%s-%s",
					strings.ToLower(container),
					lowerReason,
				)
			}
		} else {
			// This is a Pod event.
			//
			// Expected output: pod-<reason>
			//
			// Example(s):
			// - pod-scheduled
			// - pod-created
			// - pod-deleted
			event.Check.ObjectMeta.Name = fmt.Sprintf(
				"pod-%s",
				lowerReason,
			)
		}
	case "replicaset":
		// Parse replicaset event.message values like "Created pod:
		// nginx-bbd465f66-rwb2d" by splitting the string on "pod:".
		if len(strings.Split(lowerMessage, "pod:")) == 2 {
			// This is a Replicaset/Pod event (i.e. an event that is associated
			// with a K8s Replicaset resource, with reference to a specific Pod
			// that is managed by the Replicaset). Replicaset/Pod event names are
			// prefixed with "pod-" for verbosity. NOTE: Replicaset/Pod events are
			// also associated with the underlying Pod entity; see "switch lowerKind"
			// (below) for more information.
			//
			// Expected output: pod-<reason>
			//
			// Example(s):
			// - pod-scheduled
			// - pod-created
			// - pod-deleted
			//
			// Many replicaset events have messages like "Created pod:
			// nginx-bbd465f66-rwb2d". We want to capture the first word
			// in this string as the event "verb".
			verb := strings.ToLower(msgFields[0])
			event.Check.ObjectMeta.Name = fmt.Sprintf(
				"pod-%s",
				verb,
			)
		} else {
			// This is a Replicaset event.
			//
			// Expected output: replicaset-<reason>
			//
			// Example(s):
			// - replicaset-deleted
			event.Check.ObjectMeta.Name = strings.ToLower(
				fmt.Sprintf(
					"replicaset-%s",
					k8sEvent.Reason,
				),
			)
		}
	case "deployment":
		if len(strings.Split(lowerMessage, "replica set")) == 2 {
			// This is a Deployment/ReplicaSet event (i.e. an event that is associated
			// with a K8s Deployment resource, with reference to a specific ReplicaSet
			// that is managed by the Deployment). Deployment/Replicaset event names
			// are prefixed with "replicaset" for verbosity. Deployment/Replicaset
			// event names need to reference ReplicaSet names to avoid event name
			// collisions (e.g. replicaset-influxdb-12345-deleted vs
			// replicaset-influxdb-67890-deleted).
			//
			// Expected output: replicaset-<replicaset_name>-<reason>
			//
			// Example(s):
			// - replicaset-nginx-12345-deleted
			message := strings.Split(lowerMessage, "replica set")
			replicaset := strings.Fields(message[1])[0] // first word after "replica set"
			event.Check.ObjectMeta.Name = fmt.Sprintf(
				"replicaset-%s-%s",
				strings.ToLower(replicaset),
				lowerReason,
			)
		} else {
			// This is a Deployment event.
			//
			// Expected output: <deployment_name>-<reason>
			//
			// Example(s):
			// - nginx-deleted
			event.Check.ObjectMeta.Name = fmt.Sprintf(
				"%s-%s",
				lowerName,
				lowerReason,
			)
		}
	case "endpoints":
		// This is an Endpoint event.
		//
		// Expected output: endpoint-<endpoint_name>-<reason>
		event.Check.ObjectMeta.Name = fmt.Sprintf(
			"endpoint-%s-%s",
			lowerName,
			lowerReason,
		)
	case "node":
		// NOTE: Node deletion event "reason" field values appear to be quite
		// inconsistent compared to other Node events.
		if strings.HasPrefix(lowerReason, "deleting node") {

			event.Check.ObjectMeta.Name = "deletingnode"
		} else {
			// Most node events have pretty clean "reason" field values
			event.Check.ObjectMeta.Name = lowerReason
		}
	default:
		if len(msgFields) == 2 && msgFields[0] == "Error:" {
			// If we have a definitive single word error message, use that as the check name
			event.Check.ObjectMeta.Name = msgFields[1]
		} else {
			// This is a valid event that we don't have special handling for. If you
			// see one of these events, please open a GitHub issue with a copy of the
			// K8s event data so we can improve the plugin. Thanks!!
			//
			// Expected output: <kube_resource_name>.<kube_event_id>
			//
			// Example(s):
			// - nginx-bbd465f66.162cb9a548a2a604
			//
			// NOTE: these event names can be used to collect the underlying K8s
			// event; e.g.: kubectl describe event nginx-bbd465f66.162cb9a548a2a604
			event.Check.ObjectMeta.Name = k8sEvent.ObjectMeta.Name
		}
	}

	// Sensu Entity
	switch lowerKind {
	case "replicaset":
		message := strings.Split(k8sEvent.Message, "pod:")
		if len(message) == 2 {
			// This is a Replicaset/Pod event (i.e. an event that is associated with
			// a K8s Replicaset resource, with reference to a specific Pod that is
			// managed by the Replicaset).
			//
			// Expected output: <pod_name>
			//
			// Example(s):
			// - nginx-77587cf6cd-m5mzq
			pod := strings.ToLower(strings.Fields(message[1])[0])
			event.Check.ProxyEntityName = pod
		} else {
			// This is a ReplicaSet event.
			//
			// Expected output: <replicaset_name>
			//
			// Example(s):
			// - nginx-77587cf6cd
			event.Check.ProxyEntityName = lowerName
		}
	case "pod", "deployment", "endpoints", "node":
		// Use Kubernetes event resource names for the Sensu Entity name (i.e.
		// no special handling required).
		event.Check.ProxyEntityName = lowerName
		if plugin.GrafanaMutatorIntegration {
			event.Check.ObjectMeta.Labels = make(map[string]string)
			event.Check.ObjectMeta.Labels[lowerKind] = lowerName
			if plugin.AddClusterAnnotation != "" {
				event.Check.ObjectMeta.Labels["cluster"] = plugin.AddClusterAnnotation
			}
			if lowerKind != "node" {
				event.Check.ObjectMeta.Labels["namespace"] = k8sEvent.ObjectMeta.Namespace
			}
		}

	default:
		// This is a valid event that we don't have special handling for. If you
		// see an event associated with a Sensu entity that is suffixed with the
		// K8s "kind", please open a GitHub issue with a copy of the K8s event data
		// so we can improve the plugin. Thanks!!
		event.Check.ProxyEntityName = fmt.Sprintf(
			"%s-%s",
			lowerName,
			lowerKind,
		)
	}
	// add replicaset, pod, deployment, endpoints, node label
	// labelName := fmt.Sprintf("io.kubernetes.%s", lowerReason)
	// event.ObjectMeta.Labels[labelName] = lowerReason

	// Event status mapping
	status, err := getSensuEventStatus(k8sEvent.Type)
	if err != nil {
		return &corev2.Event{}, err
	}
	event.Check.Status = status
	// overwrite sensu namespace
	if plugin.SensuNamespace != "" {
		event.Check.ObjectMeta.Namespace = plugin.SensuNamespace
	}

	// overwrite proxy entity name
	if plugin.SensuProxyEntity != "" {
		// add check label
		event.ObjectMeta.Labels["io.kubernetes.check"] = event.Check.Name
		// first make any check unique
		event.Check.Name = fmt.Sprintf("%s-%s", event.Check.Name, event.Check.ProxyEntityName)
		// then replace proxy entity
		event.Check.ProxyEntityName = plugin.SensuProxyEntity

	}

	// Populate the remaining Sensu event details
	event.Timestamp = k8sEvent.LastTimestamp.Time.Unix()
	event.Check.Interval = plugin.Interval
	event.Check.Handlers = plugin.Handlers
	event.Check.Output = fmt.Sprintf(
		"Event for %s %s in namespace %s, reason: %q, message: %q\n",
		k8sEvent.InvolvedObject.Kind,
		k8sEvent.ObjectMeta.Name,
		k8sEvent.ObjectMeta.Namespace,
		k8sEvent.Reason,
		k8sEvent.Message,
	)

	if plugin.SensuExtraLabel != "" {
		extraLabels := parseLabelArg(plugin.SensuExtraLabel)
		// log.Println(extraLabels)
		if event.Check.Labels != nil {
			event.Check.Labels = mergeStringMaps(event.Check.Labels, extraLabels)
		} else {
			event.Check.Labels = extraLabels
		}

	}
	if plugin.SensuExtraAnnotation != "" {
		extraAnnotations := parseLabelArg(plugin.SensuExtraAnnotation)
		// log.Println(extraAnnotations)
		if event.Check.Annotations != nil {
			event.Check.Annotations = mergeStringMaps(event.Check.Annotations, extraAnnotations)
		} else {
			event.Check.Annotations = extraAnnotations
		}

	}

	return event, nil
}

func submitEventAgentAPI(event *corev2.Event) error {

	encoded, _ := json.Marshal(event)
	resp, err := http.Post(plugin.AgentAPIURL, "application/json", bytes.NewBuffer(encoded))
	if err != nil {
		return fmt.Errorf("Failed to post event to %s failed: %v", plugin.AgentAPIURL, err)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("POST of event to %s failed with status %v\nevent: %s", plugin.AgentAPIURL, resp.Status, string(encoded))
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

// authenticate funcion to wotk with api-backend-* flags
func authenticate() (Auth, error) {
	var auth Auth
	client := http.DefaultClient
	client.Transport = http.DefaultTransport

	if plugin.Secure {
		client.Transport.(*http.Transport).TLSClientConfig = &tlsConfig
	}

	req, err := http.NewRequest(
		"GET",
		fmt.Sprintf("%s://%s:%d/auth", plugin.Protocol, plugin.APIBackendHost, plugin.APIBackendPort),
		nil,
	)
	if err != nil {
		return auth, fmt.Errorf("error generating auth request: %v", err)
	}

	req.SetBasicAuth(plugin.APIBackendUser, plugin.APIBackendPass)

	resp, err := client.Do(req)
	if err != nil {
		return auth, fmt.Errorf("error executing auth request: %v", err)
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return auth, fmt.Errorf("error reading auth response: %v", err)
	}

	if strings.HasPrefix(string(body), "Unauthorized") {
		return auth, fmt.Errorf("authorization failed for user %s", plugin.APIBackendUser)
	}

	err = json.NewDecoder(bytes.NewReader(body)).Decode(&auth)

	if err != nil {
		trim := 64
		return auth, fmt.Errorf("error decoding auth response: %v\nFirst %d bytes of response: %s", err, trim, trimBody(body, trim))
	}

	return auth, err
}

// get events from sensu-backend-api
func getEvents(auth Auth, namespace string) ([]*types.Event, error) {
	client := http.DefaultClient
	client.Transport = http.DefaultTransport

	url := fmt.Sprintf("%s://%s:%d/api/core/v2/namespaces/%s/events", plugin.Protocol, plugin.APIBackendHost, plugin.APIBackendPort, namespace)
	events := []*types.Event{}

	if plugin.Secure {
		client.Transport.(*http.Transport).TLSClientConfig = &tlsConfig
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return events, fmt.Errorf("error creating GET request for %s: %v", url, err)
	}

	if len(plugin.APIBackendKey) == 0 {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", auth.AccessToken))
	} else {
		req.Header.Set("Authorization", fmt.Sprintf("Key %s", plugin.APIBackendKey))
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return events, fmt.Errorf("error executing GET request for %s: %v", url, err)
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return events, fmt.Errorf("error reading response body during getEvents: %v", err)
	}

	err = json.Unmarshal(body, &events)
	if err != nil {
		trim := 64
		return events, fmt.Errorf("error unmarshalling response during getEvents: %v\nFirst %d bytes of response: %s", err, trim, trimBody(body, trim))
	}
	result := filterEvents(events)
	return result, err
}

// filter events from sensu-backend-api to look only events created by this plugin
func filterEvents(events []*types.Event) (result []*types.Event) {
	matchLabels := make(map[string]string)
	if plugin.SensuAutoCloseLabel != "" {
		err := json.Unmarshal([]byte(plugin.SensuAutoCloseLabel), &matchLabels)
		if err != nil {
			fmt.Println("fail in SensuAutoCloseLabel Unmarshal")
			return result
		}
	}
	for _, event := range events {
		if event.ObjectMeta.Labels[plugin.Name] == "owner" && event.Check.Status != 0 {
			// if AutoCloseLabel is not empty and label match
			if plugin.SensuAutoCloseLabel != "" && searchLabels(event, matchLabels) {
				result = append(result, event)
			}
		}
	}
	return result
}

// used to clean errors output
func trimBody(body []byte, maxlen int) string {
	if len(string(body)) < maxlen {
		maxlen = len(string(body))
	}

	return string(body)[0:maxlen]
}

func checkKubernetesEventID(alerts *k8scorev1.EventList, f string) bool {
	for _, a := range alerts.Items {
		if a.ObjectMeta.Name == f {
			return true
		}
	}
	return false
}

func searchLabels(event *types.Event, labels map[string]string) bool {
	if len(labels) == 0 {
		return false
	}
	count := 0
	for key, value := range labels {
		if event.Labels != nil {
			for k, v := range event.Labels {
				if k == key && v == value {
					count++
				}
			}
		}
		if event.Entity.Labels != nil {
			for k, v := range event.Entity.Labels {
				if k == key && v == value {
					count++
				}
			}
		}
		if event.Check.Labels != nil {
			for k, v := range event.Check.Labels {
				if k == key && v == value {
					count++
				}
			}
		}
		if count == len(labels) {
			return true
		}
	}

	return false
}

// parse selector labels to filter then in Alert Manager alerts endpoint
func parseLabelArg(labelArg string) map[string]string {
	labels := map[string]string{}

	pairs := strings.Split(labelArg, ",")

	for _, pair := range pairs {
		parts := strings.Split(pair, "=")
		if len(parts) == 2 {
			labels[parts[0]] = parts[1]
		}
	}

	return labels
}

func mergeStringMaps(left, right map[string]string) map[string]string {
	for k, v := range right {
		// fmt.Println(left[k])
		if left[k] == "" {
			left[k] = v
		}
	}
	return left
}

func stringToSliceStrings(s string) []string {
	slice := []string{}
	if s != "" {
		if strings.Contains(s, ",") {
			splited := strings.Split(s, ",")
			for _, v := range splited {
				if v != "" {
					slice = append(slice, v)
				}
			}
		} else {
			slice = []string{s}
		}
	}
	return slice
}

// use to parse annotations to send as link
func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}
