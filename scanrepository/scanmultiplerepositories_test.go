package scanrepository

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp/capability"
	"github.com/jfrog/frogbot/v2/utils"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/stretchr/testify/assert"
)

var testScanMultipleRepositoriesConfigPath = filepath.Join("..", "testdata", "config", "frogbot-config-scan-multiple-repositories.yml")
var testRepositories = []string{"pip-repo", "npm-repo", "mvn-repo"}

func TestScanAndFixRepos(t *testing.T) {
	serverParams, restoreEnv := utils.VerifyEnv(t)
	defer restoreEnv()
	_, restoreJfrogHomeFunc := utils.CreateTempJfrogHomeWithCallback(t)
	defer restoreJfrogHomeFunc()

	baseWd, err := os.Getwd()
	assert.NoError(t, err)

	var port string
	server := httptest.NewServer(createScanRepoGitHubHandler(t, &port, nil, testRepositories...))
	defer server.Close()
	port = server.URL[strings.LastIndex(server.URL, ":")+1:]
	client, err := vcsclient.NewClientBuilder(vcsutils.GitHub).ApiEndpoint(server.URL).Token("123456").Build()
	assert.NoError(t, err)

	// Create a temporary file for SARIF output
	tmpFile, err := os.CreateTemp("", "sarifOutputPath-*.sarif")
	assert.NoError(t, err, "Temporary file for SARIF path should be created successfully")
	defer os.Remove(tmpFile.Name()) // Clean up the file at the end of the test
	// Use the temporary file's path as sarifPath
	sarifPath := tmpFile.Name()

	gitTestParams := utils.Git{
		GitProvider: vcsutils.GitHub,
		RepoOwner:   "jfrog",
		VcsInfo: vcsclient.VcsInfo{
			Token:       "123456",
			APIEndpoint: server.URL,
		},
	}

	configData, err := utils.ReadConfigFromFileSystem(testScanMultipleRepositoriesConfigPath)
	assert.NoError(t, err)

	testDir, cleanup := utils.CopyTestdataProjectsToTemp(t, "scanmultiplerepositories")
	defer func() {
		assert.NoError(t, os.Chdir(baseWd))
		cleanup()
	}()

	utils.CreateDotGitWithCommit(t, testDir, port, testRepositories...)
	configAggregator, err := utils.BuildRepoAggregator(client, configData, &gitTestParams, &serverParams, utils.ScanMultipleRepositories)
	assert.NoError(t, err)

	var cmd = ScanMultipleRepositories{dryRun: true, dryRunRepoPath: testDir}
	assert.NoError(t, cmd.Run(configAggregator, client, utils.MockHasConnection(), sarifPath))
}

func createScanRepoGitHubHandler(t *testing.T, port *string, response interface{}, projectNames ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		for _, projectName := range projectNames {
			if r.RequestURI == fmt.Sprintf("/%s/info/refs?service=git-upload-pack", projectName) {
				hash := plumbing.NewHash("5e3021cf22da163f0d312d8fcf299abaa79726fb")
				capabilities := capability.NewList()
				assert.NoError(t, capabilities.Add(capability.SymRef, "HEAD:/refs/heads/master"))
				ar := &packp.AdvRefs{
					References: map[string]plumbing.Hash{
						"refs/heads/master": plumbing.NewHash("5e3021cf22da163f0d312d8fcf299abaa79726fb"),
					},
					Head:         &hash,
					Capabilities: capabilities,
				}
				var buf bytes.Buffer
				assert.NoError(t, ar.Encode(&buf))
				_, err := w.Write(buf.Bytes())
				assert.NoError(t, err)
				w.WriteHeader(http.StatusOK)
				return
			}
			if r.RequestURI == fmt.Sprintf("/repos/jfrog/%s/pulls", projectName) {
				w.WriteHeader(http.StatusOK)
				return
			}
			if r.RequestURI == fmt.Sprintf("/%s", projectName) {
				file, err := os.ReadFile(fmt.Sprintf("%s.tar.gz", projectName))
				assert.NoError(t, err)
				_, err = w.Write(file)
				assert.NoError(t, err)
				return
			}
			if r.RequestURI == fmt.Sprintf("/repos/jfrog/%s/tarball/master", projectName) {
				w.Header().Add("Location", fmt.Sprintf("http://127.0.0.1:%s/%s", *port, projectName))
				w.WriteHeader(http.StatusFound)
				_, err := w.Write([]byte{})
				assert.NoError(t, err)
				return
			}
			if r.RequestURI == fmt.Sprintf("/repos/jfrog/%s/commits?page=1&per_page=%d&sha=master", projectName, vcsutils.NumberOfCommitsToFetch) {
				w.WriteHeader(http.StatusOK)
				rawJson := "[\n  {\n    \"url\": \"https://api.github.com/repos/octocat/Hello-World/commits/6dcb09b5b57875f334f61aebed695e2e4193db5e\",\n    \"sha\": \"6dcb09b5b57875f334f61aebed695e2e4193db5e\",\n    \"node_id\": \"MDY6Q29tbWl0NmRjYjA5YjViNTc4NzVmMzM0ZjYxYWViZWQ2OTVlMmU0MTkzZGI1ZQ==\",\n    \"html_url\": \"https://github.com/octocat/Hello-World/commit/6dcb09b5b57875f334f61aebed695e2e4193db5e\",\n    \"comments_url\": \"https://api.github.com/repos/octocat/Hello-World/commits/6dcb09b5b57875f334f61aebed695e2e4193db5e/comments\",\n    \"commit\": {\n      \"url\": \"https://api.github.com/repos/octocat/Hello-World/git/commits/6dcb09b5b57875f334f61aebed695e2e4193db5e\",\n      \"author\": {\n        \"name\": \"Monalisa Octocat\",\n        \"email\": \"support@github.com\",\n        \"date\": \"2011-04-14T16:00:49Z\"\n      },\n      \"committer\": {\n        \"name\": \"Monalisa Octocat\",\n        \"email\": \"support@github.com\",\n        \"date\": \"2011-04-14T16:00:49Z\"\n      },\n      \"message\": \"Fix all the bugs\",\n      \"tree\": {\n        \"url\": \"https://api.github.com/repos/octocat/Hello-World/tree/6dcb09b5b57875f334f61aebed695e2e4193db5e\",\n        \"sha\": \"6dcb09b5b57875f334f61aebed695e2e4193db5e\"\n      },\n      \"comment_count\": 0,\n      \"verification\": {\n        \"verified\": false,\n        \"reason\": \"unsigned\",\n        \"signature\": null,\n        \"payload\": null\n      }\n    },\n    \"author\": {\n      \"login\": \"octocat\",\n      \"id\": 1,\n      \"node_id\": \"MDQ6VXNlcjE=\",\n      \"avatar_url\": \"https://github.com/images/error/octocat_happy.gif\",\n      \"gravatar_id\": \"\",\n      \"url\": \"https://api.github.com/users/octocat\",\n      \"html_url\": \"https://github.com/octocat\",\n      \"followers_url\": \"https://api.github.com/users/octocat/followers\",\n      \"following_url\": \"https://api.github.com/users/octocat/following{/other_user}\",\n      \"gists_url\": \"https://api.github.com/users/octocat/gists{/gist_id}\",\n      \"starred_url\": \"https://api.github.com/users/octocat/starred{/owner}{/repo}\",\n      \"subscriptions_url\": \"https://api.github.com/users/octocat/subscriptions\",\n      \"organizations_url\": \"https://api.github.com/users/octocat/orgs\",\n      \"repos_url\": \"https://api.github.com/users/octocat/repos\",\n      \"events_url\": \"https://api.github.com/users/octocat/events{/privacy}\",\n      \"received_events_url\": \"https://api.github.com/users/octocat/received_events\",\n      \"type\": \"User\",\n      \"site_admin\": false\n    },\n    \"committer\": {\n      \"login\": \"octocat\",\n      \"id\": 1,\n      \"node_id\": \"MDQ6VXNlcjE=\",\n      \"avatar_url\": \"https://github.com/images/error/octocat_happy.gif\",\n      \"gravatar_id\": \"\",\n      \"url\": \"https://api.github.com/users/octocat\",\n      \"html_url\": \"https://github.com/octocat\",\n      \"followers_url\": \"https://api.github.com/users/octocat/followers\",\n      \"following_url\": \"https://api.github.com/users/octocat/following{/other_user}\",\n      \"gists_url\": \"https://api.github.com/users/octocat/gists{/gist_id}\",\n      \"starred_url\": \"https://api.github.com/users/octocat/starred{/owner}{/repo}\",\n      \"subscriptions_url\": \"https://api.github.com/users/octocat/subscriptions\",\n      \"organizations_url\": \"https://api.github.com/users/octocat/orgs\",\n      \"repos_url\": \"https://api.github.com/users/octocat/repos\",\n      \"events_url\": \"https://api.github.com/users/octocat/events{/privacy}\",\n      \"received_events_url\": \"https://api.github.com/users/octocat/received_events\",\n      \"type\": \"User\",\n      \"site_admin\": false\n    },\n    \"parents\": [\n      {\n        \"url\": \"https://api.github.com/repos/octocat/Hello-World/commits/6dcb09b5b57875f334f61aebed695e2e4193db5e\",\n        \"sha\": \"6dcb09b5b57875f334f61aebed695e2e4193db5e\"\n      }\n    ]\n  }\n]"
				b := []byte(rawJson)
				_, err := w.Write(b)
				assert.NoError(t, err)
				return
			}
			if r.RequestURI == fmt.Sprintf("/repos/jfrog/%v/code-scanning/sarifs", projectName) {
				w.WriteHeader(http.StatusAccepted)
				rawJson := "{\n  \"id\": \"47177e22-5596-11eb-80a1-c1e54ef945c6\",\n  \"url\": \"https://api.github.com/repos/octocat/hello-world/code-scanning/sarifs/47177e22-5596-11eb-80a1-c1e54ef945c6\"\n}"
				b := []byte(rawJson)
				_, err := w.Write(b)
				assert.NoError(t, err)
				return
			}
			if r.RequestURI == fmt.Sprintf("/repos/jfrog/%s/pulls?state=open", projectName) {
				jsonResponse, err := json.Marshal(response)
				assert.NoError(t, err)
				_, err = w.Write(jsonResponse)
				assert.NoError(t, err)
				return
			}
			if r.RequestURI == fmt.Sprintf("/repos/jfrog/%s", projectName) {
				jsonResponse := `{"id": 1296269,"node_id": "MDEwOlJlcG9zaXRvcnkxMjk2MjY5","name": "Hello-World","full_name": "octocat/Hello-World","private": false,"description": "This your first repo!","ssh_url": "git@github.com:octocat/Hello-World.git","clone_url": "https://github.com/octocat/Hello-World.git","visibility": "public"}`
				_, err := w.Write([]byte(jsonResponse))
				assert.NoError(t, err)
				return
			}
		}
	}
}
