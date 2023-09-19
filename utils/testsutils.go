package utils

import (
	"fmt"
	"github.com/go-git/go-git/v5"
	goGitConfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing/object"
	biutils "github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// Receive an environment variables key-values map, set and assert the environment variables.
// Return a callback that sets the previous values.
func SetEnvAndAssert(t *testing.T, env map[string]string) {
	for key, val := range env {
		setEnvAndAssert(t, key, val)
	}
}

// Make sure the environment variables does not contain any Frogbot variables
func AssertSanitizedEnv(t *testing.T) {
	for _, env := range os.Environ() {
		assert.False(t, strings.HasPrefix(env, "JF_"))
	}
}

func setEnvAndAssert(t *testing.T, key, value string) {
	assert.NoError(t, os.Setenv(key, value))
}

// Prepare test environment for the integration tests
// projectName - the directory name under testDir
// Return a cleanup function and the temp dir path
func PrepareTestEnvironment(t *testing.T, testDir string) (tmpDir string, restoreFunc func()) {
	// Copy project to a temporary directory
	tmpDir, err := fileutils.CreateTempDir()
	assert.NoError(t, err)
	err = biutils.CopyDir(filepath.Join("..", "testdata", testDir), tmpDir, true, []string{})
	assert.NoError(t, err)
	restoreFunc = func() {
		assert.NoError(t, fileutils.RemoveTempDir(tmpDir))
	}
	return
}

// Check connection details with JFrog instance.
// Return a callback method that restores the credentials after the test is done.
func VerifyEnv(t *testing.T) (server config.ServerDetails, restoreFunc func()) {
	url := strings.TrimSuffix(os.Getenv(JFrogUrlEnv), "/")
	username := os.Getenv(JFrogUserEnv)
	password := os.Getenv(JFrogPasswordEnv)
	token := os.Getenv(JFrogTokenEnv)
	if url == "" {
		assert.FailNow(t, fmt.Sprintf("'%s' is not set", JFrogUrlEnv))
	}
	if token == "" && (username == "" || password == "") {
		assert.FailNow(t, fmt.Sprintf("'%s' or '%s' and '%s' are not set", JFrogTokenEnv, JFrogUserEnv, JFrogPasswordEnv))
	}
	server.Url = url
	server.XrayUrl = url + "/xray/"
	server.ArtifactoryUrl = url + "/artifactory/"
	server.User = username
	server.Password = password
	server.AccessToken = token
	restoreFunc = func() {
		SetEnvAndAssert(t, map[string]string{
			JFrogUrlEnv:          url,
			JFrogTokenEnv:        token,
			JFrogUserEnv:         username,
			JFrogPasswordEnv:     password,
			GitAggregateFixesEnv: "FALSE",
		})
	}
	return
}

func CreateDotGitWithCommit(t *testing.T, wd, port string, repositoriesPath ...string) {
	for _, repositoryPath := range repositoriesPath {
		fullWdPath := filepath.Join(wd, repositoryPath)
		dotGit, err := git.PlainInit(fullWdPath, false)
		assert.NoError(t, err)
		_, err = dotGit.CreateRemote(&goGitConfig.RemoteConfig{
			Name: "origin",
			URLs: []string{fmt.Sprintf("http://127.0.0.1:%s/%s", port, repositoryPath)},
		})
		assert.NoError(t, err)
		worktree, err := dotGit.Worktree()
		assert.NoError(t, err)
		assert.NoError(t, worktree.AddWithOptions(&git.AddOptions{All: true}))
		_, err = worktree.Commit("first commit", &git.CommitOptions{
			Author: &object.Signature{
				Name:  "JFrog-Frogbot",
				Email: "eco-system+frogbot@jfrog.com",
				When:  time.Now(),
			},
		})
		assert.NoError(t, err)
	}
}

func GetRunWithDummyResults(results ...*sarif.Result) *sarif.Run {
	run := sarif.NewRunWithInformationURI("", "")
	ids := datastructures.MakeSet[string]()
	for _, result := range results {
		if !ids.Exists(*result.RuleID) {
			run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, sarif.NewRule(*result.RuleID))
			ids.Add(*result.RuleID)
		}
	}
	return run.WithResults(results)
}

func GetDummyPassingResult(ruleId string) *sarif.Result {
	kind := "pass"
	return &sarif.Result{
		Kind:   &kind,
		RuleID: &ruleId,
	}
}

func GetDummyResultWithOneLocation(fileName string, startLine, startCol int, snippet, ruleId string, level string) *sarif.Result {
	return &sarif.Result{
		Locations: []*sarif.Location{
			{
				PhysicalLocation: &sarif.PhysicalLocation{
					ArtifactLocation: &sarif.ArtifactLocation{URI: &fileName},
					Region: &sarif.Region{
						StartLine:   &startLine,
						StartColumn: &startCol,
						Snippet:     &sarif.ArtifactContent{Text: &snippet}}},
			},
		},
		Level:  &level,
		RuleID: &ruleId,
	}
}
