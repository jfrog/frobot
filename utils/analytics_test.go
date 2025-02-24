package utils

import (
	"testing"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	xscservices "github.com/jfrog/jfrog-client-go/xsc/services"
	"github.com/stretchr/testify/assert"
)

func TestCreateAnalyticsGeneralEvent(t *testing.T) {
	gitInfoContext := &xscservices.XscGitInfoContext{
		Source: xscservices.CommitContext{
			GitRepoHttpsCloneUrl: "http://localhost:8080/my-user/my-project.git",
			GitRepoName:          "my-project",
			GitProject:           "my-user",
			BranchName:           "main",
			CommitHash:           "a23ba44a0d379dida668nmb72003a82e4e11d0ba",
			CommitMessage:        ".",
			CommitAuthor:         "User",
		},
		GitProvider:  "GitHub",
		Technologies: nil,
	}

	serverDetails := &config.ServerDetails{
		Url:            "http://localhost:8080/",
		ArtifactoryUrl: "http://localhost:8080/artifactory/",
		XscUrl:         "http://localhost:8080/xray/",
		User:           "user",
		Password:       "password",
	}

	analyticsGeneralEvent := CreateScanEvent(serverDetails, gitInfoContext, "monitor")

	// Comparison is made manually for selected fields since some of the fields are machine-dependent and cannot be known in advance
	assert.Equal(t, xscservices.FrogbotType, analyticsGeneralEvent.EventType)
	assert.Equal(t, xscservices.Started, analyticsGeneralEvent.EventStatus)
	assert.Equal(t, xscservices.FrogbotProduct, analyticsGeneralEvent.Product)
	assert.Equal(t, "user", analyticsGeneralEvent.JfrogUser)
	assert.Equal(t, "monitor", analyticsGeneralEvent.FrogbotScanType)
	assert.Equal(t, gitInfoContext, analyticsGeneralEvent.GitInfo)
	assert.True(t, analyticsGeneralEvent.IsGitInfoFlow)
	assert.NotEmpty(t, analyticsGeneralEvent.ProductVersion)
	assert.NotEmpty(t, analyticsGeneralEvent.OsPlatform)
	assert.NotEmpty(t, analyticsGeneralEvent.OsArchitecture)
	assert.NotEmpty(t, analyticsGeneralEvent.AnalyzerManagerVersion)
}
