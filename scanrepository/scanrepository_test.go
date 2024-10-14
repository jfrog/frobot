package scanrepository

import (
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-github/v45/github"
	biutils "github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/frogbot/v2/utils"
	"github.com/jfrog/frogbot/v2/utils/outputwriter"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-security/formats"
	xrayutils "github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const rootTestDir = "scanrepository"

var testPackagesData = []struct {
	packageType string
	commandName string
	commandArgs []string
}{
	{
		packageType: techutils.Go.String(),
	},
	{
		packageType: techutils.Maven.String(),
	},
	{
		packageType: techutils.Gradle.String(),
	},
	{
		packageType: techutils.Npm.String(),
		commandName: "npm",
		commandArgs: []string{"install"},
	},
	{
		packageType: "yarn1",
		commandName: "yarn",
		commandArgs: []string{"install"},
	},
	{
		packageType: "yarn2",
		commandName: "yarn",
		commandArgs: []string{"install"},
	},
	{
		packageType: techutils.Dotnet.String(),
		commandName: "dotnet",
		commandArgs: []string{"restore"},
	},
	{
		packageType: techutils.Nuget.String(),
		commandName: "nuget",
		commandArgs: []string{"restore"},
	},
	{
		packageType: techutils.Pip.String(),
	},
	{
		packageType: techutils.Pipenv.String(),
	},
	{
		packageType: techutils.Poetry.String(),
	},
}

func TestScanRepositoryCmd_Run(t *testing.T) {
	tests := []struct {
		testName                       string
		configPath                     string
		expectedPackagesInBranch       map[string][]string
		expectedVersionUpdatesInBranch map[string][]string
		packageDescriptorPaths         []string
		aggregateFixes                 bool
		allowPartialResults            bool
	}{
		{
			testName:                       "aggregate",
			expectedPackagesInBranch:       map[string][]string{"frogbot-update-npm-dependencies-master": {"uuid", "minimist", "mpath"}},
			expectedVersionUpdatesInBranch: map[string][]string{"frogbot-update-npm-dependencies-master": {"^1.2.6", "^9.0.0", "^0.8.4"}},
			packageDescriptorPaths:         []string{"package.json"},
			aggregateFixes:                 true,
		},
		{
			testName:                       "aggregate-multi-dir",
			expectedPackagesInBranch:       map[string][]string{"frogbot-update-npm-dependencies-master": {"uuid", "minimatch", "mpath", "minimist"}},
			expectedVersionUpdatesInBranch: map[string][]string{"frogbot-update-npm-dependencies-master": {"^1.2.6", "^9.0.0", "^0.8.4", "^3.0.5"}},
			packageDescriptorPaths:         []string{"npm1/package.json", "npm2/package.json"},
			aggregateFixes:                 true,
			configPath:                     "../testdata/scanrepository/cmd/aggregate-multi-dir/.frogbot/frogbot-config.yml",
		},
		{
			testName:                       "aggregate-multi-project",
			expectedPackagesInBranch:       map[string][]string{"frogbot-update-npm-dependencies-master": {"uuid", "minimatch", "mpath"}, "frogbot-update-Pip-dependencies-master": {"pyjwt", "pexpect"}},
			expectedVersionUpdatesInBranch: map[string][]string{"frogbot-update-npm-dependencies-master": {"^9.0.0", "^0.8.4", "^3.0.5"}, "frogbot-update-Pip-dependencies-master": {"2.4.0"}},
			packageDescriptorPaths:         []string{"npm/package.json", "pip/requirements.txt"},
			aggregateFixes:                 true,
			configPath:                     "../testdata/scanrepository/cmd/aggregate-multi-project/.frogbot/frogbot-config.yml",
		},
		{
			testName: "aggregate-no-vul",
			// No branch is being created because there are no vulnerabilities.
			expectedPackagesInBranch:       map[string][]string{"master": {}},
			expectedVersionUpdatesInBranch: map[string][]string{"master": {}},
			packageDescriptorPaths:         []string{"package.json"},
			aggregateFixes:                 true,
		},
		{
			testName: "aggregate-cant-fix",
			// Branch name stays master as no new branch is being created
			expectedPackagesInBranch:       map[string][]string{"master": {}},
			expectedVersionUpdatesInBranch: map[string][]string{"master": {}},
			// This is a build tool dependency which should not be fixed.
			packageDescriptorPaths: []string{"setup.py"},
			aggregateFixes:         true,
		},
		{
			testName:                       "non-aggregate",
			expectedPackagesInBranch:       map[string][]string{"frogbot-minimist-258ad6a538b5ba800f18ae4f6d660302": {"minimist"}},
			expectedVersionUpdatesInBranch: map[string][]string{"frogbot-minimist-258ad6a538b5ba800f18ae4f6d660302": {"^1.2.6"}},
			packageDescriptorPaths:         []string{"package.json"},
			aggregateFixes:                 false,
		},
		{
			// This testcase checks the partial results feature. It simulates a failure in the dependency tree construction in the test's project inner module
			testName:                       "partial-results-enabled",
			expectedPackagesInBranch:       map[string][]string{"frogbot-update-npm-dependencies-master": {"minimist", "mpath"}},
			expectedVersionUpdatesInBranch: map[string][]string{"frogbot-update-npm-dependencies-master": {"1.2.6", "0.8.4"}},
			packageDescriptorPaths:         []string{"package.json", "inner-project/package.json"},
			aggregateFixes:                 true,
			configPath:                     "../testdata/scanrepository/cmd/partial-results-enabled/.frogbot/frogbot-config.yml",
			allowPartialResults:            true,
		},
	}
	baseDir, err := os.Getwd()
	assert.NoError(t, err)
	testDir, cleanup := utils.CopyTestdataProjectsToTemp(t, filepath.Join(rootTestDir, "cmd"))
	defer cleanup()
	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			// Prepare
			serverParams, restoreEnv := utils.VerifyEnv(t)
			defer restoreEnv()
			if test.aggregateFixes {
				assert.NoError(t, os.Setenv(utils.GitAggregateFixesEnv, "true"))
				defer func() {
					assert.NoError(t, os.Setenv(utils.GitAggregateFixesEnv, "false"))
				}()
			}
			if test.allowPartialResults {
				assert.NoError(t, os.Setenv(utils.AllowPartialResultsEnv, "true"))
				defer func() {
					assert.NoError(t, os.Setenv(utils.AllowPartialResultsEnv, "false"))
				}()
			}
			var port string
			server := httptest.NewServer(createScanRepoGitHubHandler(t, &port, nil, test.testName))
			defer server.Close()
			port = server.URL[strings.LastIndex(server.URL, ":")+1:]
			gitTestParams := utils.Git{
				GitProvider: vcsutils.GitHub,
				VcsInfo: vcsclient.VcsInfo{
					Token:       "123456",
					APIEndpoint: server.URL,
				},
				RepoName:  test.testName,
				RepoOwner: "jfrog",
			}
			client, err := vcsclient.NewClientBuilder(vcsutils.GitHub).ApiEndpoint(server.URL).Token("123456").Build()
			assert.NoError(t, err)

			// Read config or resolve to default
			var configData []byte
			if test.configPath != "" {
				configData, err = utils.ReadConfigFromFileSystem(test.configPath)
				assert.NoError(t, err)
			} else {
				configData = []byte{}
				// Manual set of "JF_GIT_BASE_BRANCH"
				gitTestParams.Branches = []string{"master"}
			}
			// Create a temporary file for SARIF output in this test case
			tmpFile, err := os.CreateTemp("", "sarifOutputPath-*.sarif")
			assert.NoError(t, err, "Temporary file for SARIF path should be created successfully")
			defer os.Remove(tmpFile.Name()) // Clean up the file at the end of the test

			// Use the temporary file's path as sarifPath
			sarifPath := tmpFile.Name()

			utils.CreateDotGitWithCommit(t, testDir, port, test.testName)
			configAggregator, err := utils.BuildRepoAggregator(client, configData, &gitTestParams, &serverParams, utils.ScanRepository)
			assert.NoError(t, err)
			// Run
			var cmd = ScanRepositoryCmd{dryRun: true, dryRunRepoPath: testDir}
			err = cmd.Run(configAggregator, client, utils.MockHasConnection(), sarifPath)
			defer func() {
				assert.NoError(t, os.Chdir(baseDir))
			}()

			// Validate
			assert.NoError(t, err)
			for branch, packages := range test.expectedPackagesInBranch {
				resultDiff, err := verifyDependencyFileDiff("master", branch, test.packageDescriptorPaths...)
				assert.NoError(t, err)
				if len(packages) > 0 {
					assert.NotEmpty(t, resultDiff)
				}
				for _, packageToUpdate := range packages {
					assert.Contains(t, string(resultDiff), packageToUpdate)
				}
				packageVersionUpdatesInBranch := test.expectedVersionUpdatesInBranch[branch]
				for _, updatedVersion := range packageVersionUpdatesInBranch {
					assert.Contains(t, string(resultDiff), updatedVersion)
				}
			}
		})
	}
}

// Tests the lifecycle of aggregated pull request
// No open pull request -> Open
// If Pull request already active, compare scan results for current and remote branch
// Same scan results -> do nothing.
// Different scan results -> Update the pull request branch & body.
func TestAggregatePullRequestLifecycle(t *testing.T) {
	mockPrId := 1
	sourceBranchName := "frogbot-update-npm-dependencies"
	targetBranchName := "main"
	sourceLabel := "repo:frogbot-update-npm-dependencies"
	targetLabel := "repo:main"
	firstBody := `
[comment]: <> (Checksum: 4608a55b621cb6337ac93487979ac09c)
pr body
`
	secondBody := `
[comment]: <> (Checksum: 01373ac4d2c32e7da9be22f3e4b4e665)
pr body
 `
	tests := []struct {
		testName                string
		expectedUpdate          bool
		mockPullRequestResponse []*github.PullRequest
	}{
		{
			testName:       "aggregate-dont-update-pr",
			expectedUpdate: false,
			mockPullRequestResponse: []*github.PullRequest{{
				Number: &mockPrId,
				Head: &github.PullRequestBranch{
					Label: &sourceLabel,
					Repo:  &github.Repository{Name: &sourceBranchName, Owner: &github.User{}},
				},
				Base: &github.PullRequestBranch{
					Label: &targetLabel,
					Repo:  &github.Repository{Name: &targetBranchName, Owner: &github.User{}},
				},
				Body: &firstBody,
			}},
		},
		{
			testName:       "aggregate-update-pr",
			expectedUpdate: true,
			mockPullRequestResponse: []*github.PullRequest{{
				Number: &mockPrId,
				Head: &github.PullRequestBranch{
					Label: &sourceLabel,
					Repo:  &github.Repository{Name: &sourceBranchName, Owner: &github.User{}},
				},
				Base: &github.PullRequestBranch{
					Label: &targetLabel,
					Repo:  &github.Repository{Name: &targetBranchName, Owner: &github.User{}},
				},
				Body: &secondBody,
			}},
		},
	}

	baseDir, err := os.Getwd()
	assert.NoError(t, err)
	serverParams, restoreEnv := utils.VerifyEnv(t)
	defer restoreEnv()
	testDir, cleanup := utils.CopyTestdataProjectsToTemp(t, filepath.Join(rootTestDir, "aggregate-pr-lifecycle"))
	defer cleanup()
	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			var port string
			server := httptest.NewServer(createScanRepoGitHubHandler(t, &port, test.mockPullRequestResponse, test.testName))
			defer server.Close()
			port = server.URL[strings.LastIndex(server.URL, ":")+1:]

			assert.NoError(t, os.Setenv(utils.GitAggregateFixesEnv, "true"))
			defer func() {
				assert.NoError(t, os.Setenv(utils.GitAggregateFixesEnv, "false"))
			}()

			gitTestParams := &utils.Git{
				GitProvider: vcsutils.GitHub,
				RepoOwner:   "jfrog",
				VcsInfo: vcsclient.VcsInfo{
					Token:       "123456",
					APIEndpoint: server.URL,
				}, RepoName: test.testName,
			}
			// Create a temporary file for SARIF output in this test case
			tmpFile, err := os.CreateTemp("", "sarifOutputPath-*.sarif")
			assert.NoError(t, err, "Temporary file for SARIF path should be created successfully")
			defer os.Remove(tmpFile.Name()) // Clean up the file at the end of the test

			// Use the temporary file's path as sarifPath
			sarifPath := tmpFile.Name()

			utils.CreateDotGitWithCommit(t, testDir, port, test.testName)
			client, err := vcsclient.NewClientBuilder(vcsutils.GitHub).ApiEndpoint(server.URL).Token("123456").Build()
			assert.NoError(t, err)
			// Load default configurations
			var configData []byte
			gitTestParams.Branches = []string{"master"}
			configAggregator, err := utils.BuildRepoAggregator(client, configData, gitTestParams, &serverParams, utils.ScanRepository)
			assert.NoError(t, err)
			// Run
			var cmd = ScanRepositoryCmd{dryRun: true, dryRunRepoPath: testDir}
			err = cmd.Run(configAggregator, client, utils.MockHasConnection(), sarifPath)
			defer func() {
				assert.NoError(t, os.Chdir(baseDir))
			}()
			assert.NoError(t, err)
		})
	}
}

// /      1.0         --> 1.0 ≤ x
// /      (,1.0]      --> x ≤ 1.0
// /      (,1.0)      --> x < 1.0
// /      [1.0]       --> x == 1.0
// /      (1.0,)      --> 1.0 < x
// /      (1.0, 2.0)   --> 1.0 < x < 2.0
// /      [1.0, 2.0]   --> 1.0 ≤ x ≤ 2.0
func TestParseVersionChangeString(t *testing.T) {
	tests := []struct {
		versionChangeString string
		expectedVersion     string
	}{
		{"1.2.3", "1.2.3"},
		{"[1.2.3]", "1.2.3"},
		{"[1.2.3, 2.0.0]", "1.2.3"},

		{"(,1.2.3]", ""},
		{"(,1.2.3)", ""},
		{"(1.2.3,)", ""},
		{"(1.2.3, 2.0.0)", ""},
	}

	for _, test := range tests {
		t.Run(test.versionChangeString, func(t *testing.T) {
			assert.Equal(t, test.expectedVersion, parseVersionChangeString(test.versionChangeString))
		})
	}
}

func TestGenerateFixBranchName(t *testing.T) {
	tests := []struct {
		baseBranch      string
		impactedPackage string
		fixVersion      string
		expectedName    string
	}{
		{"dev", "gopkg.in/yaml.v3", "3.0.0", "frogbot-gopkg.in/yaml.v3-d61bde82dc594e5ccc5a042fe224bf7c"},
		{"master", "gopkg.in/yaml.v3", "3.0.0", "frogbot-gopkg.in/yaml.v3-41405528994061bd108e3bbd4c039a03"},
		{"dev", "replace:colons:colons", "3.0.0", "frogbot-replace_colons_colons-89e555131b4a70a32fe9d9c44d6ff0fc"},
	}
	gitManager := utils.GitManager{}
	for _, test := range tests {
		t.Run(test.expectedName, func(t *testing.T) {
			branchName, err := gitManager.GenerateFixBranchName(test.baseBranch, test.impactedPackage, test.fixVersion)
			assert.NoError(t, err)
			assert.Equal(t, test.expectedName, branchName)
		})
	}
}

func TestPackageTypeFromScan(t *testing.T) {
	environmentVars, restoreEnv := utils.VerifyEnv(t)
	defer restoreEnv()
	testScan := &ScanRepositoryCmd{OutputWriter: &outputwriter.StandardOutput{}}
	trueVal := true
	params := utils.Params{
		Scan: utils.Scan{Projects: []utils.Project{{UseWrapper: &trueVal}}},
	}
	var frogbotParams = utils.Repository{
		Server: environmentVars,
		Params: params,
	}
	for _, pkg := range testPackagesData {
		// Create temp technology project
		projectPath := filepath.Join("..", "testdata", "projects", pkg.packageType)
		t.Run(pkg.packageType, func(t *testing.T) {
			tmpDir, err := fileutils.CreateTempDir()
			defer func() {
				err = fileutils.RemoveTempDir(tmpDir)
			}()
			assert.NoError(t, err)
			assert.NoError(t, biutils.CopyDir(projectPath, tmpDir, true, nil))
			if pkg.packageType == techutils.Gradle.String() {
				assert.NoError(t, os.Chmod(filepath.Join(tmpDir, "gradlew"), 0777))
				assert.NoError(t, os.Chmod(filepath.Join(tmpDir, "gradlew.bat"), 0777))
			}
			frogbotParams.Projects[0].WorkingDirs = []string{tmpDir}
			files, err := fileutils.ListFiles(tmpDir, true)
			assert.NoError(t, err)
			for _, file := range files {
				log.Info(file)
			}
			frogbotParams.Projects[0].InstallCommandName = pkg.commandName
			frogbotParams.Projects[0].InstallCommandArgs = pkg.commandArgs
			scanSetup := utils.ScanDetails{
				XrayGraphScanParams: &services.XrayGraphScanParams{},
				Project:             &frogbotParams.Projects[0],
				ServerDetails:       &frogbotParams.Server,
			}
			testScan.scanDetails = &scanSetup
			scanResponse, err := testScan.scan(tmpDir)
			require.NoError(t, err)
			verifyTechnologyNaming(t, scanResponse.GetScaScansXrayResults(), pkg.packageType)
		})
	}
}

func TestGetMinimalFixVersion(t *testing.T) {
	tests := []struct {
		impactedVersionPackage string
		fixVersions            []string
		expected               string
	}{
		{impactedVersionPackage: "1.6.2", fixVersions: []string{"1.5.3", "1.6.1", "1.6.22", "1.7.0"}, expected: "1.6.22"},
		{impactedVersionPackage: "v1.6.2", fixVersions: []string{"1.5.3", "1.6.1", "1.6.22", "1.7.0"}, expected: "1.6.22"},
		{impactedVersionPackage: "1.7.1", fixVersions: []string{"1.5.3", "1.6.1", "1.6.22", "1.7.0"}, expected: ""},
		{impactedVersionPackage: "1.7.1", fixVersions: []string{"2.5.3"}, expected: "2.5.3"},
		{impactedVersionPackage: "v1.7.1", fixVersions: []string{"0.5.3", "0.9.9"}, expected: ""},
	}
	for _, test := range tests {
		t.Run(test.expected, func(t *testing.T) {
			expected := getMinimalFixVersion(test.impactedVersionPackage, test.fixVersions)
			assert.Equal(t, test.expected, expected)
		})
	}
}

func TestCreateVulnerabilitiesMap(t *testing.T) {
	cfp := &ScanRepositoryCmd{}

	testCases := []struct {
		name            string
		scanResults     *xrayutils.Results
		isMultipleRoots bool
		expectedMap     map[string]*utils.VulnerabilityDetails
	}{
		{
			name: "Scan results with no violations and vulnerabilities",
			scanResults: &xrayutils.Results{
				ExtendedScanResults: &xrayutils.ExtendedScanResults{},
			},
			expectedMap: map[string]*utils.VulnerabilityDetails{},
		},
		{
			name: "Scan results with vulnerabilities and no violations",
			scanResults: &xrayutils.Results{
				ScaResults: []*xrayutils.ScaScanResult{{
					XrayResults: []services.ScanResponse{
						{
							Vulnerabilities: []services.Vulnerability{
								{
									Cves: []services.Cve{
										{Id: "CVE-2023-1234", CvssV3Score: "9.1"},
										{Id: "CVE-2023-4321", CvssV3Score: "8.9"},
									},
									Severity: "Critical",
									Components: map[string]services.Component{
										"vuln1": {
											FixedVersions: []string{"1.9.1", "2.0.3", "2.0.5"},
											ImpactPaths:   [][]services.ImpactPathNode{{{ComponentId: "root"}, {ComponentId: "vuln1"}}},
										},
									},
								},
								{
									Cves: []services.Cve{
										{Id: "CVE-2022-1234", CvssV3Score: "7.1"},
										{Id: "CVE-2022-4321", CvssV3Score: "7.9"},
									},
									Severity: "High",
									Components: map[string]services.Component{
										"vuln2": {
											FixedVersions: []string{"2.4.1", "2.6.3", "2.8.5"},
											ImpactPaths:   [][]services.ImpactPathNode{{{ComponentId: "root"}, {ComponentId: "vuln1"}, {ComponentId: "vuln2"}}},
										},
									},
								},
							},
						},
					},
				}},
				ExtendedScanResults: &xrayutils.ExtendedScanResults{},
			},
			expectedMap: map[string]*utils.VulnerabilityDetails{
				"vuln1": {
					SuggestedFixedVersion: "1.9.1",
					IsDirectDependency:    true,
					Cves:                  []string{"CVE-2023-1234", "CVE-2023-4321"},
				},
				"vuln2": {
					SuggestedFixedVersion: "2.4.1",
					Cves:                  []string{"CVE-2022-1234", "CVE-2022-4321"},
				},
			},
		},
		{
			name: "Scan results with violations and no vulnerabilities",
			scanResults: &xrayutils.Results{
				ScaResults: []*xrayutils.ScaScanResult{{
					XrayResults: []services.ScanResponse{
						{
							Violations: []services.Violation{
								{
									ViolationType: "security",
									Cves: []services.Cve{
										{Id: "CVE-2023-1234", CvssV3Score: "9.1"},
										{Id: "CVE-2023-4321", CvssV3Score: "8.9"},
									},
									Severity: "Critical",
									Components: map[string]services.Component{
										"viol1": {
											FixedVersions: []string{"1.9.1", "2.0.3", "2.0.5"},
											ImpactPaths:   [][]services.ImpactPathNode{{{ComponentId: "root"}, {ComponentId: "viol1"}}},
										},
									},
								},
								{
									ViolationType: "security",
									Cves: []services.Cve{
										{Id: "CVE-2022-1234", CvssV3Score: "7.1"},
										{Id: "CVE-2022-4321", CvssV3Score: "7.9"},
									},
									Severity: "High",
									Components: map[string]services.Component{
										"viol2": {
											FixedVersions: []string{"2.4.1", "2.6.3", "2.8.5"},
											ImpactPaths:   [][]services.ImpactPathNode{{{ComponentId: "root"}, {ComponentId: "viol1"}, {ComponentId: "viol2"}}},
										},
									},
								},
							},
						},
					},
				}},
				ExtendedScanResults: &xrayutils.ExtendedScanResults{},
			},
			expectedMap: map[string]*utils.VulnerabilityDetails{
				"viol1": {
					SuggestedFixedVersion: "1.9.1",
					IsDirectDependency:    true,
					Cves:                  []string{"CVE-2023-1234", "CVE-2023-4321"},
				},
				"viol2": {
					SuggestedFixedVersion: "2.4.1",
					Cves:                  []string{"CVE-2022-1234", "CVE-2022-4321"},
				},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			fixVersionsMap, err := cfp.createVulnerabilitiesMap(testCase.scanResults, testCase.isMultipleRoots)
			assert.NoError(t, err)
			for name, expectedVuln := range testCase.expectedMap {
				actualVuln, exists := fixVersionsMap[name]
				require.True(t, exists)
				assert.Equal(t, expectedVuln.IsDirectDependency, actualVuln.IsDirectDependency)
				assert.Equal(t, expectedVuln.SuggestedFixedVersion, actualVuln.SuggestedFixedVersion)
				assert.ElementsMatch(t, expectedVuln.Cves, actualVuln.Cves)
			}
		})
	}
}

// Verifies unsupported packages return specific error
// Other logic is implemented inside each package-handler.
func TestUpdatePackageToFixedVersion(t *testing.T) {
	var testScan ScanRepositoryCmd
	for tech, buildToolsDependencies := range utils.BuildToolsDependenciesMap {
		for _, impactedDependency := range buildToolsDependencies {
			vulnDetails := &utils.VulnerabilityDetails{SuggestedFixedVersion: "3.3.3", VulnerabilityOrViolationRow: formats.VulnerabilityOrViolationRow{Technology: tech, ImpactedDependencyDetails: formats.ImpactedDependencyDetails{ImpactedDependencyName: impactedDependency}}, IsDirectDependency: true}
			err := testScan.updatePackageToFixedVersion(vulnDetails)
			assert.Error(t, err, "Expected error to occur")
			assert.IsType(t, &utils.ErrUnsupportedFix{}, err, "Expected unsupported fix error")
		}
	}
}

func TestGetRemoteBranchScanHash(t *testing.T) {
	prBody := `
a body

[Comment]: <> (Checksum: myhash4321)
`
	cfp := &ScanRepositoryCmd{}
	result := cfp.getRemoteBranchScanHash(prBody)
	assert.Equal(t, "myhash4321", result)
	prBody = `
random body
`
	result = cfp.getRemoteBranchScanHash(prBody)
	assert.Equal(t, "", result)
}

func TestPreparePullRequestDetails(t *testing.T) {
	cfp := ScanRepositoryCmd{OutputWriter: &outputwriter.StandardOutput{}, gitManager: &utils.GitManager{}}
	cfp.OutputWriter.SetJasOutputFlags(true, false)
	vulnerabilities := []*utils.VulnerabilityDetails{
		{
			VulnerabilityOrViolationRow: formats.VulnerabilityOrViolationRow{
				Summary: "summary",
				ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
					SeverityDetails:           formats.SeverityDetails{Severity: "High", SeverityNumValue: 10},
					ImpactedDependencyName:    "package1",
					ImpactedDependencyVersion: "1.0.0",
				},
				FixedVersions: []string{"1.0.0", "2.0.0"},
				Cves:          []formats.CveRow{{Id: "CVE-2022-1234"}},
			},
			SuggestedFixedVersion: "1.0.0",
		},
	}
	expectedPrBody, expectedExtraComments := utils.GenerateFixPullRequestDetails(utils.ExtractVulnerabilitiesDetailsToRows(vulnerabilities), cfp.OutputWriter)
	prTitle, prBody, extraComments, err := cfp.preparePullRequestDetails(vulnerabilities...)
	assert.NoError(t, err)
	assert.Equal(t, "[🐸 Frogbot] Update version of package1 to 1.0.0", prTitle)
	assert.Equal(t, expectedPrBody, prBody)
	assert.ElementsMatch(t, expectedExtraComments, extraComments)
	vulnerabilities = append(vulnerabilities, &utils.VulnerabilityDetails{
		VulnerabilityOrViolationRow: formats.VulnerabilityOrViolationRow{
			Summary: "summary",
			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
				SeverityDetails:           formats.SeverityDetails{Severity: "Critical", SeverityNumValue: 12},
				ImpactedDependencyName:    "package2",
				ImpactedDependencyVersion: "2.0.0",
			},
			FixedVersions: []string{"2.0.0", "3.0.0"},
			Cves:          []formats.CveRow{{Id: "CVE-2022-4321"}},
		},
		SuggestedFixedVersion: "2.0.0",
	})
	cfp.aggregateFixes = true
	expectedPrBody, expectedExtraComments = utils.GenerateFixPullRequestDetails(utils.ExtractVulnerabilitiesDetailsToRows(vulnerabilities), cfp.OutputWriter)
	expectedPrBody += outputwriter.MarkdownComment("Checksum: bec823edaceb5d0478b789798e819bde")
	prTitle, prBody, extraComments, err = cfp.preparePullRequestDetails(vulnerabilities...)
	assert.NoError(t, err)
	assert.Equal(t, cfp.gitManager.GenerateAggregatedPullRequestTitle([]techutils.Technology{}), prTitle)
	assert.Equal(t, expectedPrBody, prBody)
	assert.ElementsMatch(t, expectedExtraComments, extraComments)
	cfp.OutputWriter = &outputwriter.SimplifiedOutput{}
	expectedPrBody, expectedExtraComments = utils.GenerateFixPullRequestDetails(utils.ExtractVulnerabilitiesDetailsToRows(vulnerabilities), cfp.OutputWriter)
	expectedPrBody += outputwriter.MarkdownComment("Checksum: bec823edaceb5d0478b789798e819bde")
	prTitle, prBody, extraComments, err = cfp.preparePullRequestDetails(vulnerabilities...)
	assert.NoError(t, err)
	assert.Equal(t, cfp.gitManager.GenerateAggregatedPullRequestTitle([]techutils.Technology{}), prTitle)
	assert.Equal(t, expectedPrBody, prBody)
	assert.ElementsMatch(t, expectedExtraComments, extraComments)
}

func verifyTechnologyNaming(t *testing.T, scanResponse []services.ScanResponse, expectedType string) {
	for _, resp := range scanResponse {
		for _, vulnerability := range resp.Vulnerabilities {
			assert.Equal(t, expectedType, vulnerability.Technology)
		}
	}
}

// Executing git diff to ensure that the intended changes to the dependent file have been made
func verifyDependencyFileDiff(baseBranch string, fixBranch string, packageDescriptorPaths ...string) (output []byte, err error) {
	log.Debug(fmt.Sprintf("Checking differences in %s between branches %s and %s", packageDescriptorPaths, baseBranch, fixBranch))
	// Suppress condition always false warning
	//goland:noinspection ALL
	var args []string
	if coreutils.IsWindows() {
		args = []string{"/c", "git", "diff", baseBranch, fixBranch}
		args = append(args, packageDescriptorPaths...)
		output, err = exec.Command("cmd", args...).Output()
	} else {
		args = []string{"diff", baseBranch, fixBranch}
		args = append(args, packageDescriptorPaths...)
		output, err = exec.Command("git", args...).Output()
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		err = errors.New("git error: " + string(exitError.Stderr))
	}
	return
}
