package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func init() {
	MinimumPluginVersion = "1.4"
	MinimumKubectlVersion = "1.14.0"
}

func TestValidate(t *testing.T) {
	testcases := []struct {
		name           string
		pluginVersion  string
		kubectlVersion string
		msg            string
	}{
		{
			name:           "versions are newer than minimum",
			pluginVersion:  "1.5",
			kubectlVersion: "1.16.9",
			msg:            "",
		},
		{
			name:           "versions are equal to minimum",
			pluginVersion:  "1.4",
			kubectlVersion: "1.14.0",
			msg:            "",
		},
		{
			name:           "plugin version is less than minimum",
			pluginVersion:  "1.2",
			kubectlVersion: "1.14.0",
			msg:            `unsupported version "1.2" of k8sldapctl. minimum version required is "1.4"`,
		},
		{
			name:           "kubectl version is less than minimum",
			pluginVersion:  "1.4",
			kubectlVersion: "1.13.0",
			msg:            `unsupported version "1.13.0" of kubectl. minimum version required is "1.14.0"`,
		},
		{
			name:           "kubectl version is not set",
			pluginVersion:  "1.4",
			kubectlVersion: "",
			msg:            `parsing user version of kubectl: Malformed version: `,
		},
		{
			name:           "k8sldapctl version is not set",
			pluginVersion:  "",
			kubectlVersion: "1.14.0",
			msg:            `parsing user version of k8sldapctl plugin: Malformed version: `,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			err := Validate(tc.pluginVersion, tc.kubectlVersion)
			if tc.msg != "" {
				assert.EqualError(t, err, tc.msg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
