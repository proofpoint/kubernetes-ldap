package client

import (
	"fmt"

	hversion "github.com/hashicorp/go-version"
	"github.com/pkg/errors"
)

var (
	//MinimumPluginVersion is the minimum version of k8sldapctl plugin required
	MinimumPluginVersion = "1.5"

	//MinimumKubectlVersion is the minimum version of kubectl required
	MinimumKubectlVersion = "1.16.0"
)

//Validate validates the client version
func Validate(pluginVersion, kubectlVersion string) error {
	err := validatePluginVersion(pluginVersion)
	if err != nil {
		return err
	}

	return validateKubectlVersion(kubectlVersion)
}

func validatePluginVersion(version string) error {
	minVersion, err := hversion.NewVersion(MinimumPluginVersion)
	if err != nil {
		return errors.Wrap(err, "parsing minimum version of k8sldapctl plugin")
	}

	currentVersion, err := hversion.NewVersion(version)
	if err != nil {
		return errors.Wrap(err, "parsing user version of k8sldapctl plugin")
	}

	if currentVersion.LessThan(minVersion) {
		return fmt.Errorf("unsupported version %q of k8sldapctl. minimum version required is %q", version, MinimumPluginVersion)
	}

	return nil
}

func validateKubectlVersion(version string) error {
	minVersion, err := hversion.NewVersion(MinimumKubectlVersion)
	if err != nil {
		return errors.Wrap(err, "parsing minimum version of kubectl")
	}

	currentVersion, err := hversion.NewVersion(version)
	if err != nil {
		return errors.Wrap(err, "parsing user version of kubectl")
	}

	if currentVersion.LessThan(minVersion) {
		return fmt.Errorf("unsupported version %q of kubectl. minimum version required is %q", version, MinimumKubectlVersion)
	}

	return nil
}
