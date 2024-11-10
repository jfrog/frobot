package packagehandlers

import (
	"github.com/jfrog/frogbot/v2/utils"
	goUtils "github.com/jfrog/jfrog-cli-core/v2/artifactory/commands/golang"
)

type GoPackageHandler struct {
	CommonPackageHandler
}

func (golang *GoPackageHandler) UpdateDependency(vulnerabilityDetails *utils.VulnerabilityDetails) error {
	// Configure resolution from an Artifactory server if needed
	if golang.depsRepo != "" {
		if err := goUtils.SetArtifactoryAsResolutionServer(golang.serverDetails, golang.depsRepo, goUtils.GoProxyUrlParams{}); err != nil {
			return err
		}
	}
	// In Golang, we can address every dependency as a direct dependency.
	return golang.CommonPackageHandler.UpdateDependency(vulnerabilityDetails, vulnerabilityDetails.Technology.GetPackageInstallationCommand())
}
