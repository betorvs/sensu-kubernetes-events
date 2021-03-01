package main

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/sensu-community/sensu-plugin-sdk/sensu"
	corev2 "github.com/sensu/sensu-go/api/core/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8scorev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestMain(t *testing.T) {
}

func TestCheckArgs(t *testing.T) {
	assert := assert.New(t)
	plugin.External = true
	plugin.EventType = "Normal"
	plugin.AgentAPIURL = "http://127.0.0.1:3031/events"
	event := corev2.FixtureEvent("entity1", "check1")
	status, err := checkArgs(event)
	assert.NoError(err)
	assert.Equal(sensu.CheckStateOK, status)
	assert.Equal("=Normal", plugin.EventType)
	assert.Equal("default", plugin.Namespace)
	plugin.Namespace = "all"
	status, err = checkArgs(event)
	assert.NoError(err)
	assert.Equal(sensu.CheckStateOK, status)
	assert.Equal(0, len(plugin.Namespace))
}

func TestCreateSensuEvent(t *testing.T) {
	const (
		k8sObjName    = "k8s-a0b1c2d3e4-event.a0b1c2d3e4f5a6b7"
		k8sInvObjName = "k8s-0a1b2c3d4e-object.0a1b2c3d4e5f6a7b"
	)

	testcases := []struct {
		k8sInvObjKind      string
		k8sInvObjFieldPath string
		k8sType            string
		k8sReason          string
		k8sMessage         string
		evStatus           uint32
		evEntityName       string
		evCheckName        string
	}{
		{
			"Pod",
			"",
			"Warning",
			"Failed",
			"Error: ImagePullBackOff",
			1,
			k8sInvObjName,
			"pod-failed",
		},
		{
			"Pod",
			"spec.containers{myservice}",
			"Warning",
			"Failed",
			"Error: ImagePullBackOff",
			1,
			k8sInvObjName,
			"container-myservice-imagepullbackoff",
		},
		{
			"Pod",
			"spec.containers{myservice}",
			"Normal",
			"Pulling",
			"Pulling image \"wrongimage:latest\"",
			0,
			k8sInvObjName,
			"container-myservice-pulling",
		},
		{
			"Node",
			"spec.containers{myservice}",
			"Warning",
			"Failed",
			"Error: ImagePullBackOff",
			1,
			k8sInvObjName,
			"failed",
		},
		{
			"Cluster",
			"spec.containers{myservice}",
			"Warning",
			"Failed",
			"Error: BackOff",
			1,
			k8sInvObjName + "-cluster",
			"BackOff",
		},
		{
			"ReplicaSet",
			"",
			"Normal",
			"SuccessfulDelete",
			"Deleted pod: myservice-bbd465f66-nbrpw",
			0,
			"myservice-bbd465f66-nbrpw",
			"pod-deleted",
		},
		{
			"ReplicaSet",
			"",
			"Normal",
			"NoOp", //fake
			"Verbed object: myservice-bbd465f66-nbrpw", // fake to not contain pod:
			0,
			k8sInvObjName,
			"replicaset-noop",
		},
		{
			"Deployment",
			"",
			"Normal",
			"NoOp", //fake
			"Verbed replica set deployment-bbd465f66", // fake to contain replica set
			0,
			k8sInvObjName,
			"replicaset-deployment-bbd465f66-noop",
		},
		{
			"Deployment",
			"",
			"Normal",
			"NoOp",                      //fake
			"Verbed object: deployment", // fake to not contain replica set
			0,
			k8sInvObjName,
			k8sInvObjName + "-noop",
		},
		{
			"EndPoints",
			"",
			"Normal",
			"NoOp", //fake
			"Verbed object: endpoint-bbd465f66-nbrpw",
			0,
			k8sInvObjName,
			"endpoint-" + k8sInvObjName + "-noop",
		},
		{
			"Node",
			"",
			"Normal",
			"Deleting Node", //fake
			"Verbed object: endpoint-bbd465f66-nbrpw",
			0,
			k8sInvObjName,
			"deletingnode",
		},
		{
			"Node",
			"",
			"Normal",
			"Node-NoOp", //fake
			"Verbed object: endpoint-bbd465f66-nbrpw",
			0,
			k8sInvObjName,
			"node-noop",
		},
		{
			"UnknownKind",
			"",
			"Warning",
			"Error: Failed", //fake
			"Verbed object: endpoint-bbd465f66-nbrpw",
			1,
			k8sInvObjName + "-unknownkind",
			k8sObjName,
		},
		{
			"UnknownKind",
			"",
			"Normal",
			"Nothing to see here", //fake
			"Verbed object: endpoint-bbd465f66-nbrpw",
			0,
			k8sInvObjName + "-unknownkind",
			k8sObjName,
		},
	}

	// plugin constants
	plugin.StatusMap = `{"normal": 0, "warning": 1, "default": 3}`
	plugin.Interval = 60
	plugin.Handlers = []string{"slack"}
	plugin.PluginConfig.Name = "kubernetes-event=check"
	plugin.AddClusterAnnotation = "k8s-great-cluster"

	for _, tc := range testcases {
		assert := assert.New(t)
		k8sev := k8scorev1.Event{}
		k8sev.InvolvedObject = k8scorev1.ObjectReference{}
		k8sev.ObjectMeta = metav1.ObjectMeta{}

		// k8s event constants
		k8sev.ObjectMeta.Namespace = "namespace"
		k8sev.Count = 1
		k8sev.ObjectMeta.Name = k8sObjName
		k8sev.InvolvedObject.Name = k8sInvObjName

		// test cases
		k8sev.InvolvedObject.Kind = tc.k8sInvObjKind
		k8sev.InvolvedObject.FieldPath = tc.k8sInvObjFieldPath
		k8sev.Type = tc.k8sType
		k8sev.Reason = tc.k8sReason
		k8sev.Message = tc.k8sMessage

		ev, err := createSensuEvent(k8sev)
		assert.NoError(err)
		assert.Equal(tc.evStatus, ev.Check.Status)
		assert.Equal(tc.evEntityName, ev.Check.ProxyEntityName)
		assert.Equal(tc.evCheckName, ev.Check.ObjectMeta.Name)
		assert.Equal(plugin.AddClusterAnnotation, ev.Labels["io.kubernetes.cluster"])
	}
}

func TestSubmitEventAgentAPI(t *testing.T) {
	testcases := []struct {
		httpStatus  int
		expectError bool
	}{
		{http.StatusOK, false},
		{http.StatusBadRequest, true},
	}
	for _, tc := range testcases {
		assert := assert.New(t)
		event := corev2.FixtureEvent("entity1", "check1")
		var test = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := ioutil.ReadAll(r.Body)
			assert.NoError(err)
			eV := &corev2.Event{}
			err = json.Unmarshal(body, eV)
			require.NoError(t, err)
			w.WriteHeader(tc.httpStatus)
		}))
		_, err := url.ParseRequestURI(test.URL)
		require.NoError(t, err)
		plugin.AgentAPIURL = test.URL
		err = submitEventAgentAPI(event)
		if tc.expectError {
			assert.Error(err)
		} else {
			assert.NoError(err)
		}
	}
}

func TestGetSensuEventStatus(t *testing.T) {
	testcases := []struct {
		statusMap    string
		k8sEventType string
		status       uint32
	}{
		{`{"normal": 0, "warning": 1, "default": 3}`, "Normal", 0},
		{`{"normal": 0, "warning": 1, "default": 3}`, "Warning", 1},
		{`{"normal": 0, "warning": 1, "default": 3}`, "NoMatch", 3},
		{`{"Normal": 0, "Warning": 1, "Default": 3}`, "normal", 0},
		{`{"Normal": 0, "Warning": 1, "Default": 3}`, "warning", 1},
		{`{"Normal": 0, "Warning": 1, "Default": 3}`, "nomatch", 3},
		{`{"normal": 0, "warning": 2, "default": 3}`, "Warning", 2},
		{`{"warning": 1, "default": 3}`, "Normal", 3},
		{`{"normal": 0, "warning": 1}`, "NoMatch", 255},
	}
	for _, tc := range testcases {
		assert := assert.New(t)
		plugin.StatusMap = tc.statusMap
		st, err := getSensuEventStatus(tc.k8sEventType)
		assert.NoError(err)
		assert.Equal(tc.status, st)
	}
}

func TestSearchLabels(t *testing.T) {
	event1 := corev2.FixtureEvent("entity1", "check1")
	event1.Labels["testa"] = "valuea"
	event1.Labels["testb"] = "valueb"
	event1.Labels["testc"] = "valuec"
	labels := make(map[string]string)
	res1 := searchLabels(event1, labels)
	assert.False(t, res1)

	labels["testa"] = "valuea"
	labels["testc"] = "valuec"
	res2 := searchLabels(event1, labels)
	assert.True(t, res2)

	excludeLabels := make(map[string]string)
	excludeLabels["testc"] = "valuec"
	res3 := searchLabels(event1, excludeLabels)
	assert.True(t, res3)
}

func TestParseLabelArg(t *testing.T) {
	test1 := "OneLabel=OneValue"
	val1 := map[string]string{"OneLabel": "OneValue"}
	res1 := parseLabelArg(test1)
	assert.Equal(t, val1, res1)
	test2 := "OneLabel=OneValue,TwoLabel=TwoValue"
	val2 := map[string]string{"OneLabel": "OneValue", "TwoLabel": "TwoValue"}
	res2 := parseLabelArg(test2)
	assert.Equal(t, val2, res2)
	test3 := "OneLabelOneValue,TwoLabel=TwoValue"
	val3 := map[string]string{"TwoLabel": "TwoValue"}
	res3 := parseLabelArg(test3)
	assert.Equal(t, val3, res3)
}

func TestMergeStringMaps(t *testing.T) {
	left1 := map[string]string{"left1": "leftValue1"}
	right1 := map[string]string{"right1": "rightValue1"}
	val1 := map[string]string{"left1": "leftValue1", "right1": "rightValue1"}
	res1 := mergeStringMaps(left1, right1)
	assert.Equal(t, val1, res1)
	left2 := map[string]string{"left1": "leftValue1"}
	right2 := map[string]string{"right1": "rightValue1", "left1": "rightValueLeft1"}
	val2 := map[string]string{"left1": "leftValue1", "right1": "rightValue1"}
	res2 := mergeStringMaps(left2, right2)
	assert.Equal(t, val2, res2)
	left3 := map[string]string{"left1": "leftValue1"}
	right3 := map[string]string{}
	val3 := map[string]string{"left1": "leftValue1"}
	res3 := mergeStringMaps(left3, right3)
	assert.Equal(t, val3, res3)
	left4 := map[string]string{}
	right4 := map[string]string{"right1": "rightValue1"}
	val4 := map[string]string{"right1": "rightValue1"}
	res4 := mergeStringMaps(left4, right4)
	assert.Equal(t, val4, res4)
}
