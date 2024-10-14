package scanpullrequest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jfrog/frogbot/v2/utils"
	"github.com/jfrog/frogbot/v2/utils/outputwriter"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	coreconfig "github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/formats"
	"github.com/jfrog/jfrog-cli-security/formats/sarifutils"
	xrayutils "github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/stretchr/testify/assert"
)

const (
	testMultiDirProjConfigPath       = "testdata/config/frogbot-config-multi-dir-test-proj.yml"
	testMultiDirProjConfigPathNoFail = "testdata/config/frogbot-config-multi-dir-test-proj-no-fail.yml"
	testProjSubdirConfigPath         = "testdata/config/frogbot-config-test-proj-subdir.yml"
	testCleanProjConfigPath          = "testdata/config/frogbot-config-clean-test-proj.yml"
	testProjConfigPath               = "testdata/config/frogbot-config-test-proj.yml"
	testProjConfigPathNoFail         = "testdata/config/frogbot-config-test-proj-no-fail.yml"
	testSourceBranchName             = "pr"
	testTargetBranchName             = "master"
)

func TestCreateVulnerabilitiesRows(t *testing.T) {
	// Previous scan with only one violation - XRAY-1
	previousScan := services.ScanResponse{
		Violations: []services.Violation{
			{
				IssueId:       "XRAY-1",
				Summary:       "summary-1",
				Severity:      "high",
				Cves:          []services.Cve{},
				ViolationType: "security",
				Components:    map[string]services.Component{"component-A": {}, "component-B": {}},
			},
			{
				IssueId:       "XRAY-4",
				ViolationType: "license",
				Severity:      "low",
				LicenseKey:    "Apache-2.0",
				Components:    map[string]services.Component{"Dep-2": {}},
			},
		},
	}

	// Current scan with 2 violations - XRAY-1 and XRAY-2
	currentScan := services.ScanResponse{
		Violations: []services.Violation{
			{
				IssueId:       "XRAY-1",
				Summary:       "summary-1",
				Severity:      "high",
				ViolationType: "security",
				Components:    map[string]services.Component{"component-A": {}, "component-B": {}},
			},
			{
				IssueId:       "XRAY-2",
				Summary:       "summary-2",
				ViolationType: "security",
				Severity:      "low",
				Components:    map[string]services.Component{"component-C": {}, "component-D": {}},
			},
			{
				IssueId:       "XRAY-3",
				ViolationType: "license",
				Severity:      "low",
				LicenseKey:    "MIT",
				Components:    map[string]services.Component{"Dep-1": {}},
			},
		},
	}

	// Run createNewIssuesRows and make sure that only the XRAY-2 violation exists in the results
	securityViolationsRows, licenseViolations, err := createNewVulnerabilitiesRows(
		&xrayutils.Results{ScaResults: []*xrayutils.ScaScanResult{{XrayResults: []services.ScanResponse{previousScan}}}, ExtendedScanResults: &xrayutils.ExtendedScanResults{}},
		&xrayutils.Results{ScaResults: []*xrayutils.ScaScanResult{{XrayResults: []services.ScanResponse{currentScan}}}, ExtendedScanResults: &xrayutils.ExtendedScanResults{}},
		nil,
	)
	assert.NoError(t, err)
	assert.Len(t, licenseViolations, 1)
	assert.Len(t, securityViolationsRows, 2)
	assert.Equal(t, "XRAY-2", securityViolationsRows[0].IssueId)
	assert.Equal(t, "Low", securityViolationsRows[0].Severity)
	assert.Equal(t, "XRAY-2", securityViolationsRows[1].IssueId)
	assert.Equal(t, "Low", securityViolationsRows[1].Severity)
	assert.Equal(t, "MIT", licenseViolations[0].LicenseKey)
	assert.Equal(t, "Dep-1", licenseViolations[0].ImpactedDependencyName)

	impactedPackageOne := securityViolationsRows[0].ImpactedDependencyName
	impactedPackageTwo := securityViolationsRows[1].ImpactedDependencyName
	assert.ElementsMatch(t, []string{"component-C", "component-D"}, []string{impactedPackageOne, impactedPackageTwo})
}

func TestCreateVulnerabilitiesRowsCaseNoPrevViolations(t *testing.T) {
	// Previous scan with no violation
	previousScan := services.ScanResponse{
		Violations: []services.Violation{},
	}

	// Current scan with 2 violations - XRAY-1 and XRAY-2
	currentScan := services.ScanResponse{
		Violations: []services.Violation{
			{
				IssueId:       "XRAY-1",
				Summary:       "summary-1",
				Severity:      "high",
				ViolationType: "security",
				Components:    map[string]services.Component{"component-A": {}},
			},
			{
				IssueId:       "XRAY-2",
				Summary:       "summary-2",
				ViolationType: "security",
				Severity:      "low",
				Components:    map[string]services.Component{"component-C": {}},
			},
			{
				IssueId:       "XRAY-3",
				ViolationType: "license",
				LicenseKey:    "MIT",
				Severity:      "low",
				Components:    map[string]services.Component{"Dep-1": {}},
			},
		},
	}

	expectedVulns := []formats.VulnerabilityOrViolationRow{
		{
			IssueId: "XRAY-1",
			Summary: "summary-1",
			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
				SeverityDetails:        formats.SeverityDetails{Severity: "High", SeverityNumValue: 18},
				ImpactedDependencyName: "component-A",
			},
		},
		{
			IssueId: "XRAY-2",
			Summary: "summary-2",
			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
				SeverityDetails:        formats.SeverityDetails{Severity: "Low", SeverityNumValue: 10},
				ImpactedDependencyName: "component-C",
			},
		},
	}

	expectedLicenses := []formats.LicenseRow{
		{
			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{ImpactedDependencyName: "Dep-1"},
			LicenseKey:                "MIT",
		},
	}

	// Run createNewIssuesRows and expect both XRAY-1 and XRAY-2 violation in the results
	vulnerabilities, licenses, err := createNewVulnerabilitiesRows(
		&xrayutils.Results{ScaResults: []*xrayutils.ScaScanResult{{XrayResults: []services.ScanResponse{previousScan}}}, ExtendedScanResults: &xrayutils.ExtendedScanResults{}},
		&xrayutils.Results{ScaResults: []*xrayutils.ScaScanResult{{XrayResults: []services.ScanResponse{currentScan}}}, ExtendedScanResults: &xrayutils.ExtendedScanResults{}},
		[]string{},
	)
	assert.NoError(t, err)
	assert.Len(t, licenses, 1)
	assert.Len(t, vulnerabilities, 2)
	assert.ElementsMatch(t, expectedVulns, vulnerabilities)
	assert.Equal(t, expectedLicenses[0].ImpactedDependencyName, licenses[0].ImpactedDependencyName)
	assert.Equal(t, expectedLicenses[0].LicenseKey, licenses[0].LicenseKey)
}

func TestGetNewViolationsCaseNoNewViolations(t *testing.T) {
	// Previous scan with 2 security violations and 1 license violation - XRAY-1 and XRAY-2
	previousScan := services.ScanResponse{
		Violations: []services.Violation{
			{
				IssueId:       "XRAY-1",
				Severity:      "high",
				ViolationType: "security",
				Components:    map[string]services.Component{"component-A": {}},
			},
			{
				IssueId:       "XRAY-2",
				Summary:       "summary-2",
				ViolationType: "security",
				Severity:      "low",
				Components:    map[string]services.Component{"component-C": {}},
			},
			{
				IssueId:       "XRAY-3",
				LicenseKey:    "MIT",
				ViolationType: "license",
				Components:    map[string]services.Component{"component-B": {}},
			},
		},
	}

	// Current scan with no violation
	currentScan := services.ScanResponse{
		Violations: []services.Violation{},
	}

	// Run createNewIssuesRows and expect no violations in the results
	securityViolations, licenseViolations, err := createNewVulnerabilitiesRows(
		&xrayutils.Results{ScaResults: []*xrayutils.ScaScanResult{{XrayResults: []services.ScanResponse{previousScan}}}, ExtendedScanResults: &xrayutils.ExtendedScanResults{}},
		&xrayutils.Results{ScaResults: []*xrayutils.ScaScanResult{{XrayResults: []services.ScanResponse{currentScan}}}, ExtendedScanResults: &xrayutils.ExtendedScanResults{}},
		[]string{"MIT"},
	)
	assert.NoError(t, err)
	assert.Len(t, securityViolations, 0)
	assert.Len(t, licenseViolations, 0)
}

func TestGetNewVulnerabilities(t *testing.T) {
	// Previous scan with only one vulnerability - XRAY-1
	previousScan := services.ScanResponse{
		Vulnerabilities: []services.Vulnerability{{
			IssueId:    "XRAY-1",
			Summary:    "summary-1",
			Severity:   "high",
			Cves:       []services.Cve{{Id: "CVE-2023-1234"}},
			Components: map[string]services.Component{"component-A": {}, "component-B": {}},
			Technology: techutils.Maven.String(),
		}},
	}

	// Current scan with 2 vulnerabilities - XRAY-1 and XRAY-2
	currentScan := services.ScanResponse{
		Vulnerabilities: []services.Vulnerability{
			{
				IssueId:    "XRAY-1",
				Summary:    "summary-1",
				Severity:   "high",
				Cves:       []services.Cve{{Id: "CVE-2023-1234"}},
				Components: map[string]services.Component{"component-A": {}, "component-B": {}},
				Technology: techutils.Maven.String(),
			},
			{
				IssueId:    "XRAY-2",
				Summary:    "summary-2",
				Severity:   "low",
				Cves:       []services.Cve{{Id: "CVE-2023-4321"}},
				Components: map[string]services.Component{"component-C": {}, "component-D": {}},
				Technology: techutils.Yarn.String(),
			},
		},
	}

	expected := []formats.VulnerabilityOrViolationRow{
		{
			Summary:    "summary-2",
			Applicable: "Applicable",
			IssueId:    "XRAY-2",
			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
				SeverityDetails:        formats.SeverityDetails{Severity: "Low", SeverityNumValue: 13},
				ImpactedDependencyName: "component-C",
			},
			Cves:       []formats.CveRow{{Id: "CVE-2023-4321", Applicability: &formats.Applicability{Status: "Applicable", Evidence: []formats.Evidence{{Location: formats.Location{File: "file1", StartLine: 1, StartColumn: 10, EndLine: 2, EndColumn: 11, Snippet: "snippet"}}}}}},
			Technology: techutils.Yarn,
		},
		{
			Summary:    "summary-2",
			Applicable: "Applicable",
			IssueId:    "XRAY-2",
			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
				SeverityDetails:        formats.SeverityDetails{Severity: "Low", SeverityNumValue: 13},
				ImpactedDependencyName: "component-D",
			},
			Cves:       []formats.CveRow{{Id: "CVE-2023-4321", Applicability: &formats.Applicability{Status: "Applicable", Evidence: []formats.Evidence{{Location: formats.Location{File: "file1", StartLine: 1, StartColumn: 10, EndLine: 2, EndColumn: 11, Snippet: "snippet"}}}}}},
			Technology: techutils.Yarn,
		},
	}

	// Run createNewIssuesRows and make sure that only the XRAY-2 vulnerability exists in the results
	vulnerabilities, licenses, err := createNewVulnerabilitiesRows(
		&xrayutils.Results{
			ScaResults: []*xrayutils.ScaScanResult{{XrayResults: []services.ScanResponse{previousScan}}},
			ExtendedScanResults: &xrayutils.ExtendedScanResults{
				EntitledForJas:           true,
				ApplicabilityScanResults: []*sarif.Run{sarifutils.CreateRunWithDummyResults(sarifutils.CreateResultWithOneLocation("file1", 1, 10, 2, 11, "snippet", "applic_CVE-2023-4321", ""))},
			},
		},
		&xrayutils.Results{
			ScaResults: []*xrayutils.ScaScanResult{{XrayResults: []services.ScanResponse{currentScan}}},
			ExtendedScanResults: &xrayutils.ExtendedScanResults{
				EntitledForJas:           true,
				ApplicabilityScanResults: []*sarif.Run{sarifutils.CreateRunWithDummyResults(sarifutils.CreateResultWithOneLocation("file1", 1, 10, 2, 11, "snippet", "applic_CVE-2023-4321", ""))},
			},
		},
		nil,
	)
	assert.NoError(t, err)
	assert.Len(t, vulnerabilities, 2)
	assert.Len(t, licenses, 0)
	assert.ElementsMatch(t, expected, vulnerabilities)
}

func TestGetNewVulnerabilitiesCaseNoPrevVulnerabilities(t *testing.T) {
	// Previous scan with no vulnerabilities
	previousScan := services.ScanResponse{
		Vulnerabilities: []services.Vulnerability{},
	}

	// Current scan with 2 vulnerabilities - XRAY-1 and XRAY-2
	currentScan := services.ScanResponse{
		Vulnerabilities: []services.Vulnerability{
			{
				IssueId:             "XRAY-1",
				Summary:             "summary-1",
				Severity:            "high",
				ExtendedInformation: &services.ExtendedInformation{FullDescription: "description-1"},
				Components:          map[string]services.Component{"component-A": {}},
			},
			{
				IssueId:             "XRAY-2",
				Summary:             "summary-2",
				Severity:            "low",
				ExtendedInformation: &services.ExtendedInformation{FullDescription: "description-2"},
				Components:          map[string]services.Component{"component-B": {}},
			},
		},
	}

	expected := []formats.VulnerabilityOrViolationRow{
		{
			Summary: "summary-2",
			IssueId: "XRAY-2",
			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
				SeverityDetails:        formats.SeverityDetails{Severity: "Low", SeverityNumValue: 10},
				ImpactedDependencyName: "component-B",
			},
			JfrogResearchInformation: &formats.JfrogResearchInformation{Details: "description-2"},
		},
		{
			Summary: "summary-1",
			IssueId: "XRAY-1",
			ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
				SeverityDetails:        formats.SeverityDetails{Severity: "High", SeverityNumValue: 18},
				ImpactedDependencyName: "component-A",
			},
			JfrogResearchInformation: &formats.JfrogResearchInformation{Details: "description-1"},
		},
	}

	// Run createNewIssuesRows and expect both XRAY-1 and XRAY-2 vulnerability in the results
	vulnerabilities, licenses, err := createNewVulnerabilitiesRows(
		&xrayutils.Results{ScaResults: []*xrayutils.ScaScanResult{{XrayResults: []services.ScanResponse{previousScan}}}, ExtendedScanResults: &xrayutils.ExtendedScanResults{}},
		&xrayutils.Results{ScaResults: []*xrayutils.ScaScanResult{{XrayResults: []services.ScanResponse{currentScan}}}, ExtendedScanResults: &xrayutils.ExtendedScanResults{}},
		nil,
	)
	assert.NoError(t, err)
	assert.Len(t, vulnerabilities, 2)
	assert.Len(t, licenses, 0)
	assert.ElementsMatch(t, expected, vulnerabilities)
}

func TestGetNewVulnerabilitiesCaseNoNewVulnerabilities(t *testing.T) {
	// Previous scan with 2 vulnerabilities - XRAY-1 and XRAY-2
	previousScan := services.ScanResponse{
		Vulnerabilities: []services.Vulnerability{
			{
				IssueId:    "XRAY-1",
				Summary:    "summary-1",
				Severity:   "high",
				Components: map[string]services.Component{"component-A": {}},
			},
			{
				IssueId:    "XRAY-2",
				Summary:    "summary-2",
				Severity:   "low",
				Components: map[string]services.Component{"component-B": {}},
			},
		},
	}

	// Current scan with no vulnerabilities
	currentScan := services.ScanResponse{
		Vulnerabilities: []services.Vulnerability{},
	}

	// Run createNewIssuesRows and expect no vulnerability in the results
	vulnerabilities, licenses, err := createNewVulnerabilitiesRows(
		&xrayutils.Results{ScaResults: []*xrayutils.ScaScanResult{{XrayResults: []services.ScanResponse{previousScan}}}, ExtendedScanResults: &xrayutils.ExtendedScanResults{}},
		&xrayutils.Results{ScaResults: []*xrayutils.ScaScanResult{{XrayResults: []services.ScanResponse{currentScan}}}, ExtendedScanResults: &xrayutils.ExtendedScanResults{}},
		nil,
	)
	assert.NoError(t, err)
	assert.Len(t, vulnerabilities, 0)
	assert.Len(t, licenses, 0)
}

func TestGetAllIssues(t *testing.T) {
	allowedLicenses := []string{"MIT"}
	auditResults := &xrayutils.Results{
		ScaResults: []*xrayutils.ScaScanResult{{
			XrayResults: []services.ScanResponse{{
				Vulnerabilities: []services.Vulnerability{
					{Cves: []services.Cve{{Id: "CVE-2022-2122"}}, Severity: "High", Components: map[string]services.Component{"Dep-1": {FixedVersions: []string{"1.2.3"}}}},
					{Cves: []services.Cve{{Id: "CVE-2023-3122"}}, Severity: "Low", Components: map[string]services.Component{"Dep-2": {FixedVersions: []string{"1.2.2"}}}},
				},
				Licenses: []services.License{{Key: "Apache-2.0", Components: map[string]services.Component{"Dep-1": {FixedVersions: []string{"1.2.3"}}}}},
			}},
		}},
		ExtendedScanResults: &xrayutils.ExtendedScanResults{
			ApplicabilityScanResults: []*sarif.Run{
				sarifutils.CreateRunWithDummyResults(
					sarifutils.CreateDummyPassingResult("applic_CVE-2023-3122"),
					sarifutils.CreateResultWithOneLocation("file1", 1, 10, 2, 11, "snippet", "applic_CVE-2022-2122", ""),
				),
			},
			IacScanResults: []*sarif.Run{
				sarifutils.CreateRunWithDummyResults(
					sarifutils.CreateResultWithLocations("Missing auto upgrade was detected", "rule", severityutils.SeverityToSarifSeverityLevel(severityutils.High).String(),
						sarifutils.CreateLocation("file1", 1, 10, 2, 11, "aws-violation"),
					),
				),
			},
			SecretsScanResults: []*sarif.Run{
				sarifutils.CreateRunWithDummyResults(
					sarifutils.CreateResultWithLocations("Secret", "rule", severityutils.SeverityToSarifSeverityLevel(severityutils.High).String(),
						sarifutils.CreateLocation("index.js", 5, 6, 7, 8, "access token exposed"),
					),
				),
			},
			SastScanResults: []*sarif.Run{
				sarifutils.CreateRunWithDummyResults(
					sarifutils.CreateResultWithLocations("XSS Vulnerability", "rule", severityutils.SeverityToSarifSeverityLevel(severityutils.High).String(),
						sarifutils.CreateLocation("file1", 1, 10, 2, 11, "snippet"),
					),
				),
			},
			EntitledForJas: true,
		},
	}
	expectedOutput := &utils.IssuesCollection{
		Vulnerabilities: []formats.VulnerabilityOrViolationRow{
			{
				Applicable:    "Applicable",
				FixedVersions: []string{"1.2.3"},
				ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
					SeverityDetails:        formats.SeverityDetails{Severity: "High", SeverityNumValue: 21},
					ImpactedDependencyName: "Dep-1",
				},
				Cves: []formats.CveRow{{Id: "CVE-2022-2122", Applicability: &formats.Applicability{Status: "Applicable", Evidence: []formats.Evidence{{Location: formats.Location{File: "file1", StartLine: 1, StartColumn: 10, EndLine: 2, EndColumn: 11, Snippet: "snippet"}}}}}},
			},
			{
				Applicable:    "Not Applicable",
				FixedVersions: []string{"1.2.2"},
				ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
					SeverityDetails:        formats.SeverityDetails{Severity: "Low", SeverityNumValue: 2},
					ImpactedDependencyName: "Dep-2",
				},
				Cves: []formats.CveRow{{Id: "CVE-2023-3122", Applicability: &formats.Applicability{Status: "Not Applicable"}}},
			},
		},
		Iacs: []formats.SourceCodeRow{
			{
				SeverityDetails: formats.SeverityDetails{
					Severity:         "High",
					SeverityNumValue: 21,
				},
				Finding: "Missing auto upgrade was detected",
				Location: formats.Location{
					File:        "file1",
					StartLine:   1,
					StartColumn: 10,
					EndLine:     2,
					EndColumn:   11,
					Snippet:     "aws-violation",
				},
			},
		},
		Secrets: []formats.SourceCodeRow{
			{
				SeverityDetails: formats.SeverityDetails{
					Severity:         "High",
					SeverityNumValue: 21,
				},
				Finding: "Secret",
				Location: formats.Location{
					File:        "index.js",
					StartLine:   5,
					StartColumn: 6,
					EndLine:     7,
					EndColumn:   8,
					Snippet:     "access token exposed",
				},
			},
		},
		Sast: []formats.SourceCodeRow{
			{
				SeverityDetails: formats.SeverityDetails{
					Severity:         "High",
					SeverityNumValue: 21,
				},
				Finding: "XSS Vulnerability",
				Location: formats.Location{
					File:        "file1",
					StartLine:   1,
					StartColumn: 10,
					EndLine:     2,
					EndColumn:   11,
					Snippet:     "snippet",
				},
			},
		},
		Licenses: []formats.LicenseRow{
			{
				LicenseKey: "Apache-2.0",
				ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
					ImpactedDependencyName: "Dep-1",
				},
			},
		},
	}

	issuesRows, err := getAllIssues(auditResults, allowedLicenses)

	if assert.NoError(t, err) {
		assert.ElementsMatch(t, expectedOutput.Vulnerabilities, issuesRows.Vulnerabilities)
		assert.ElementsMatch(t, expectedOutput.Iacs, issuesRows.Iacs)
		assert.ElementsMatch(t, expectedOutput.Secrets, issuesRows.Secrets)
		assert.ElementsMatch(t, expectedOutput.Sast, issuesRows.Sast)
		assert.ElementsMatch(t, expectedOutput.Licenses, issuesRows.Licenses)
	}
}

func TestScanPullRequest(t *testing.T) {
	tests := []struct {
		testName             string
		configPath           string
		projectName          string
		failOnSecurityIssues bool
	}{
		{
			testName:             "ScanPullRequest",
			configPath:           testProjConfigPath,
			projectName:          "test-proj",
			failOnSecurityIssues: true,
		},
		{
			testName:             "ScanPullRequestNoFail",
			configPath:           testProjConfigPathNoFail,
			projectName:          "test-proj",
			failOnSecurityIssues: false,
		},
		{
			testName:             "ScanPullRequestSubdir",
			configPath:           testProjSubdirConfigPath,
			projectName:          "test-proj-subdir",
			failOnSecurityIssues: true,
		},
		{
			testName:             "ScanPullRequestNoIssues",
			configPath:           testCleanProjConfigPath,
			projectName:          "clean-test-proj",
			failOnSecurityIssues: false,
		},
		{
			testName:             "ScanPullRequestMultiWorkDir",
			configPath:           testMultiDirProjConfigPathNoFail,
			projectName:          "multi-dir-test-proj",
			failOnSecurityIssues: false,
		},
		{
			testName:             "ScanPullRequestMultiWorkDirNoFail",
			configPath:           testMultiDirProjConfigPath,
			projectName:          "multi-dir-test-proj",
			failOnSecurityIssues: true,
		},
	}
	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			testScanPullRequest(t, test.configPath, test.projectName, test.failOnSecurityIssues)
		})
	}
}

func testScanPullRequest(t *testing.T, configPath, projectName string, failOnSecurityIssues bool) {
	params, restoreEnv := utils.VerifyEnv(t)
	defer restoreEnv()

	// Create mock GitLab server
	server := httptest.NewServer(createGitLabHandler(t, projectName))
	defer server.Close()

	configAggregator, client := prepareConfigAndClient(t, configPath, server, params)
	testDir, cleanUp := utils.CopyTestdataProjectsToTemp(t, "scanpullrequest")
	defer cleanUp()

	// Create a temporary file for SARIF output
	tmpFile, err := os.CreateTemp("", "sarifOutputPath-*.sarif")
	assert.NoError(t, err, "Temporary file for SARIF path should be created successfully")
	defer os.Remove(tmpFile.Name()) // Clean up the file at the end of the test
	// Use the temporary file's path as sarifPath
	sarifPath := tmpFile.Name()

	// Renames test git folder to .git
	currentDir := filepath.Join(testDir, projectName)
	restoreDir, err := utils.Chdir(currentDir)
	assert.NoError(t, err)
	defer func() {
		assert.NoError(t, restoreDir())
		assert.NoError(t, fileutils.RemoveTempDir(currentDir))
	}()

	// Run "frogbot scan pull request"
	var scanPullRequest ScanPullRequestCmd
	err = scanPullRequest.Run(configAggregator, client, utils.MockHasConnection(), sarifPath)
	if failOnSecurityIssues {
		assert.EqualErrorf(t, err, SecurityIssueFoundErr, "Error should be: %v, got: %v", SecurityIssueFoundErr, err)
	} else {
		assert.NoError(t, err)
	}
	_, err = os.Stat(sarifPath)
	assert.NoError(t, err, "SARIF file should exist at the specified path")

	// Check env sanitize
	err = utils.SanitizeEnv()
	assert.NoError(t, err)
	utils.AssertSanitizedEnv(t)
}

func TestVerifyGitHubFrogbotEnvironment(t *testing.T) {
	// Init mock
	client := CreateMockVcsClient(t)
	environment := "frogbot"
	client.EXPECT().GetRepositoryInfo(context.Background(), gitParams.RepoOwner, gitParams.RepoName).Return(vcsclient.RepositoryInfo{}, nil)
	client.EXPECT().GetRepositoryEnvironmentInfo(context.Background(), gitParams.RepoOwner, gitParams.RepoName, environment).Return(vcsclient.RepositoryEnvironmentInfo{Reviewers: []string{"froggy"}}, nil)
	assert.NoError(t, os.Setenv(utils.GitHubActionsEnv, "true"))

	// Run verifyGitHubFrogbotEnvironment
	err := verifyGitHubFrogbotEnvironment(client, gitParams)
	assert.NoError(t, err)
}

func TestVerifyGitHubFrogbotEnvironmentNoEnv(t *testing.T) {
	// Redirect log to avoid negative output
	previousLogger := redirectLogOutputToNil()
	defer log.SetLogger(previousLogger)

	// Init mock
	client := CreateMockVcsClient(t)
	environment := "frogbot"
	client.EXPECT().GetRepositoryInfo(context.Background(), gitParams.RepoOwner, gitParams.RepoName).Return(vcsclient.RepositoryInfo{}, nil)
	client.EXPECT().GetRepositoryEnvironmentInfo(context.Background(), gitParams.RepoOwner, gitParams.RepoName, environment).Return(vcsclient.RepositoryEnvironmentInfo{}, errors.New("404"))
	assert.NoError(t, os.Setenv(utils.GitHubActionsEnv, "true"))

	// Run verifyGitHubFrogbotEnvironment
	err := verifyGitHubFrogbotEnvironment(client, gitParams)
	assert.ErrorContains(t, err, noGitHubEnvErr)
}

func TestVerifyGitHubFrogbotEnvironmentNoReviewers(t *testing.T) {
	// Init mock
	client := CreateMockVcsClient(t)
	environment := "frogbot"
	client.EXPECT().GetRepositoryInfo(context.Background(), gitParams.RepoOwner, gitParams.RepoName).Return(vcsclient.RepositoryInfo{}, nil)
	client.EXPECT().GetRepositoryEnvironmentInfo(context.Background(), gitParams.RepoOwner, gitParams.RepoName, environment).Return(vcsclient.RepositoryEnvironmentInfo{}, nil)
	assert.NoError(t, os.Setenv(utils.GitHubActionsEnv, "true"))

	// Run verifyGitHubFrogbotEnvironment
	err := verifyGitHubFrogbotEnvironment(client, gitParams)
	assert.ErrorContains(t, err, noGitHubEnvReviewersErr)
}

func TestVerifyGitHubFrogbotEnvironmentOnPrem(t *testing.T) {
	repoConfig := &utils.Repository{
		Params: utils.Params{Git: utils.Git{
			VcsInfo: vcsclient.VcsInfo{APIEndpoint: "https://acme.vcs.io"}},
		},
	}

	// Run verifyGitHubFrogbotEnvironment
	err := verifyGitHubFrogbotEnvironment(&vcsclient.GitHubClient{}, repoConfig)
	assert.NoError(t, err)
}

func prepareConfigAndClient(t *testing.T, configPath string, server *httptest.Server, serverParams coreconfig.ServerDetails) (utils.RepoAggregator, vcsclient.VcsClient) {
	gitTestParams := &utils.Git{
		GitProvider: vcsutils.GitHub,
		RepoOwner:   "jfrog",
		VcsInfo: vcsclient.VcsInfo{
			Token:       "123456",
			APIEndpoint: server.URL,
		},
		PullRequestDetails: vcsclient.PullRequestInfo{ID: int64(1)},
	}
	utils.SetEnvAndAssert(t, map[string]string{utils.GitPullRequestIDEnv: "1"})

	client, err := vcsclient.NewClientBuilder(vcsutils.GitLab).ApiEndpoint(server.URL).Token("123456").Build()
	assert.NoError(t, err)

	configData, err := utils.ReadConfigFromFileSystem(configPath)
	assert.NoError(t, err)
	configAggregator, err := utils.BuildRepoAggregator(client, configData, gitTestParams, &serverParams, utils.ScanPullRequest)
	assert.NoError(t, err)

	return configAggregator, client
}

// Create HTTP handler to mock GitLab server
func createGitLabHandler(t *testing.T, projectName string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		// Return 200 on ping
		case r.RequestURI == "/api/v4/":
			w.WriteHeader(http.StatusOK)
		// Mimic get pull request by ID
		case r.RequestURI == fmt.Sprintf("/api/v4/projects/jfrog%s/merge_requests/1", "%2F"+projectName):
			w.WriteHeader(http.StatusOK)
			expectedResponse, err := os.ReadFile(filepath.Join("..", "expectedPullRequestDetailsResponse.json"))
			assert.NoError(t, err)
			_, err = w.Write(expectedResponse)
			assert.NoError(t, err)
		// Mimic download specific branch to scan
		case r.RequestURI == fmt.Sprintf("/api/v4/projects/jfrog%s/repository/archive.tar.gz?sha=%s", "%2F"+projectName, testSourceBranchName):
			w.WriteHeader(http.StatusOK)
			repoFile, err := os.ReadFile(filepath.Join("..", projectName, "sourceBranch.gz"))
			assert.NoError(t, err)
			_, err = w.Write(repoFile)
			assert.NoError(t, err)
		// Download repository mock
		case r.RequestURI == fmt.Sprintf("/api/v4/projects/jfrog%s/repository/archive.tar.gz?sha=%s", "%2F"+projectName, testTargetBranchName):
			w.WriteHeader(http.StatusOK)
			repoFile, err := os.ReadFile(filepath.Join("..", projectName, "targetBranch.gz"))
			assert.NoError(t, err)
			_, err = w.Write(repoFile)
			assert.NoError(t, err)
			return
		// clean-test-proj should not include any vulnerabilities so assertion is not needed.
		case r.RequestURI == fmt.Sprintf("/api/v4/projects/jfrog%s/merge_requests/133/notes", "%2Fclean-test-proj") && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte("{}"))
			assert.NoError(t, err)
			return
		case r.RequestURI == fmt.Sprintf("/api/v4/projects/jfrog%s/merge_requests/133/notes", "%2Fclean-test-proj") && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			comments, err := os.ReadFile(filepath.Join("..", "commits.json"))
			assert.NoError(t, err)
			_, err = w.Write(comments)
			assert.NoError(t, err)
		// Return 200 when using the REST that creates the comment
		case r.RequestURI == fmt.Sprintf("/api/v4/projects/jfrog%s/merge_requests/133/notes", "%2F"+projectName) && r.Method == http.MethodPost:
			buf := new(bytes.Buffer)
			_, err := buf.ReadFrom(r.Body)
			assert.NoError(t, err)
			assert.NotEmpty(t, buf.String())

			var expectedResponse []byte
			if strings.Contains(projectName, "multi-dir") {
				expectedResponse = outputwriter.GetJsonBodyOutputFromFile(t, filepath.Join("..", "expected_response_multi_dir.md"))
			} else {
				expectedResponse = outputwriter.GetJsonBodyOutputFromFile(t, filepath.Join("..", "expected_response.md"))
			}
			assert.NoError(t, err)
			assert.JSONEq(t, string(expectedResponse), buf.String())

			w.WriteHeader(http.StatusOK)
			_, err = w.Write([]byte("{}"))
			assert.NoError(t, err)
		case r.RequestURI == fmt.Sprintf("/api/v4/projects/jfrog%s/merge_requests/133/notes", "%2F"+projectName) && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			comments, err := os.ReadFile(filepath.Join("..", "commits.json"))
			assert.NoError(t, err)
			_, err = w.Write(comments)
			assert.NoError(t, err)
		case r.RequestURI == fmt.Sprintf("/api/v4/projects/jfrog%s", "%2F"+projectName):
			jsonResponse := `{"id": 3,"visibility": "private","ssh_url_to_repo": "git@example.com:diaspora/diaspora-project-site.git","http_url_to_repo": "https://example.com/diaspora/diaspora-project-site.git"}`
			_, err := w.Write([]byte(jsonResponse))
			assert.NoError(t, err)
		case r.RequestURI == fmt.Sprintf("/api/v4/projects/jfrog%s/merge_requests/133/discussions", "%2F"+projectName):
			discussions, err := os.ReadFile(filepath.Join("..", "list_merge_request_discussion_items.json"))
			assert.NoError(t, err)
			_, err = w.Write(discussions)
			assert.NoError(t, err)
		}
	}
}

func TestCreateNewIacRows(t *testing.T) {
	testCases := []struct {
		name                            string
		targetIacResults                []*sarif.Result
		sourceIacResults                []*sarif.Result
		expectedAddedIacVulnerabilities []formats.SourceCodeRow
	}{
		{
			name: "No vulnerabilities in source IaC results",
			targetIacResults: []*sarif.Result{
				sarifutils.CreateResultWithLocations("Missing auto upgrade was detected", "rule", severityutils.SeverityToSarifSeverityLevel(severityutils.High).String(),
					sarifutils.CreateLocation("file1", 1, 10, 2, 11, "aws-violation"),
				),
			},
			sourceIacResults:                []*sarif.Result{},
			expectedAddedIacVulnerabilities: []formats.SourceCodeRow{},
		},
		{
			name:             "No vulnerabilities in target IaC results",
			targetIacResults: []*sarif.Result{},
			sourceIacResults: []*sarif.Result{
				sarifutils.CreateResultWithLocations("Missing auto upgrade was detected", "rule", severityutils.SeverityToSarifSeverityLevel(severityutils.High).String(),
					sarifutils.CreateLocation("file1", 1, 10, 2, 11, "aws-violation"),
				),
			},
			expectedAddedIacVulnerabilities: []formats.SourceCodeRow{
				{
					SeverityDetails: formats.SeverityDetails{
						Severity:         "High",
						SeverityNumValue: 21,
					},
					Finding: "Missing auto upgrade was detected",
					Location: formats.Location{
						File:        "file1",
						StartLine:   1,
						StartColumn: 10,
						EndLine:     2,
						EndColumn:   11,
						Snippet:     "aws-violation",
					},
				},
			},
		},
		{
			name: "Some new vulnerabilities in source IaC results",
			targetIacResults: []*sarif.Result{
				sarifutils.CreateResultWithLocations("Missing auto upgrade was detected", "rule", severityutils.SeverityToSarifSeverityLevel(severityutils.High).String(),
					sarifutils.CreateLocation("file1", 1, 10, 2, 11, "aws-violation"),
				),
			},
			sourceIacResults: []*sarif.Result{
				sarifutils.CreateResultWithLocations("enable_private_endpoint=false was detected", "rule", severityutils.SeverityToSarifSeverityLevel(severityutils.Medium).String(),
					sarifutils.CreateLocation("file2", 2, 5, 3, 6, "gcp-violation"),
				),
			},
			expectedAddedIacVulnerabilities: []formats.SourceCodeRow{
				{
					SeverityDetails: formats.SeverityDetails{
						Severity:         "Medium",
						SeverityNumValue: 17,
					},
					Finding: "enable_private_endpoint=false was detected",
					Location: formats.Location{
						File:        "file2",
						StartLine:   2,
						StartColumn: 5,
						EndLine:     3,
						EndColumn:   6,
						Snippet:     "gcp-violation",
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			targetIacRows := xrayutils.PrepareIacs([]*sarif.Run{sarifutils.CreateRunWithDummyResults(tc.targetIacResults...)})
			sourceIacRows := xrayutils.PrepareIacs([]*sarif.Run{sarifutils.CreateRunWithDummyResults(tc.sourceIacResults...)})
			addedIacVulnerabilities := createNewSourceCodeRows(targetIacRows, sourceIacRows)
			assert.ElementsMatch(t, tc.expectedAddedIacVulnerabilities, addedIacVulnerabilities)
		})
	}
}

func TestCreateNewSecretRows(t *testing.T) {
	testCases := []struct {
		name                                string
		targetSecretsResults                []*sarif.Result
		sourceSecretsResults                []*sarif.Result
		expectedAddedSecretsVulnerabilities []formats.SourceCodeRow
	}{
		{
			name: "No vulnerabilities in source secrets results",
			targetSecretsResults: []*sarif.Result{
				sarifutils.CreateResultWithLocations("Secret", "rule", severityutils.SeverityToSarifSeverityLevel(severityutils.High).String(),
					sarifutils.CreateLocation("file1", 1, 10, 2, 11, "Sensitive information"),
				),
			},
			sourceSecretsResults:                []*sarif.Result{},
			expectedAddedSecretsVulnerabilities: []formats.SourceCodeRow{},
		},
		{
			name:                 "No vulnerabilities in target secrets results",
			targetSecretsResults: []*sarif.Result{},
			sourceSecretsResults: []*sarif.Result{
				sarifutils.CreateResultWithLocations("Secret", "rule", severityutils.SeverityToSarifSeverityLevel(severityutils.High).String(),
					sarifutils.CreateLocation("file1", 1, 10, 2, 11, "Sensitive information"),
				),
			},
			expectedAddedSecretsVulnerabilities: []formats.SourceCodeRow{
				{
					SeverityDetails: formats.SeverityDetails{
						Severity:         "High",
						SeverityNumValue: 21,
					},
					Finding: "Secret",
					Location: formats.Location{
						File:        "file1",
						StartLine:   1,
						StartColumn: 10,
						EndLine:     2,
						EndColumn:   11,
						Snippet:     "Sensitive information",
					},
				},
			},
		},
		{
			name: "Some new vulnerabilities in source secrets results",
			targetSecretsResults: []*sarif.Result{
				sarifutils.CreateResultWithLocations("Secret", "rule", severityutils.SeverityToSarifSeverityLevel(severityutils.High).String(),
					sarifutils.CreateLocation("file1", 1, 10, 2, 11, "Sensitive information"),
				),
			},
			sourceSecretsResults: []*sarif.Result{
				sarifutils.CreateResultWithLocations("Secret", "rule", severityutils.SeverityToSarifSeverityLevel(severityutils.Medium).String(),
					sarifutils.CreateLocation("file2", 2, 5, 3, 6, "Confidential data"),
				),
			},
			expectedAddedSecretsVulnerabilities: []formats.SourceCodeRow{
				{
					SeverityDetails: formats.SeverityDetails{
						Severity:         "Medium",
						SeverityNumValue: 17,
					},
					Finding: "Secret",
					Location: formats.Location{
						File:        "file2",
						StartLine:   2,
						StartColumn: 5,
						EndLine:     3,
						EndColumn:   6,
						Snippet:     "Confidential data",
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			targetSecretsRows := xrayutils.PrepareSecrets([]*sarif.Run{sarifutils.CreateRunWithDummyResults(tc.targetSecretsResults...)})
			sourceSecretsRows := xrayutils.PrepareSecrets([]*sarif.Run{sarifutils.CreateRunWithDummyResults(tc.sourceSecretsResults...)})
			addedSecretsVulnerabilities := createNewSourceCodeRows(targetSecretsRows, sourceSecretsRows)
			assert.ElementsMatch(t, tc.expectedAddedSecretsVulnerabilities, addedSecretsVulnerabilities)
		})
	}
}

func TestCreateNewSastRows(t *testing.T) {
	testCases := []struct {
		name                             string
		targetSastResults                []*sarif.Result
		sourceSastResults                []*sarif.Result
		expectedAddedSastVulnerabilities []formats.SourceCodeRow
	}{
		{
			name: "No vulnerabilities in source Sast results",
			targetSastResults: []*sarif.Result{
				sarifutils.CreateResultWithLocations("XSS Vulnerability", "rule", severityutils.SeverityToSarifSeverityLevel(severityutils.High).String(),
					sarifutils.CreateLocation("file1", 1, 10, 2, 11, "snippet"),
				),
			},
			sourceSastResults:                []*sarif.Result{},
			expectedAddedSastVulnerabilities: []formats.SourceCodeRow{},
		},
		{
			name:              "No vulnerabilities in target Sast results",
			targetSastResults: []*sarif.Result{},
			sourceSastResults: []*sarif.Result{
				sarifutils.CreateResultWithLocations("XSS Vulnerability", "rule", severityutils.SeverityToSarifSeverityLevel(severityutils.High).String(),
					sarifutils.CreateLocation("file1", 1, 10, 2, 11, "snippet"),
				),
			},
			expectedAddedSastVulnerabilities: []formats.SourceCodeRow{
				{
					SeverityDetails: formats.SeverityDetails{
						Severity:         "High",
						SeverityNumValue: 21,
					},
					Finding: "XSS Vulnerability",
					Location: formats.Location{
						File:        "file1",
						StartLine:   1,
						StartColumn: 10,
						EndLine:     2,
						EndColumn:   11,
						Snippet:     "snippet",
					},
				},
			},
		},
		{
			name: "Some new vulnerabilities in source Sast results",
			targetSastResults: []*sarif.Result{
				sarifutils.CreateResultWithLocations("XSS Vulnerability", "rule", severityutils.SeverityToSarifSeverityLevel(severityutils.High).String(),
					sarifutils.CreateLocation("file1", 1, 10, 2, 11, "snippet"),
				),
			},
			sourceSastResults: []*sarif.Result{
				sarifutils.CreateResultWithLocations("Stack Trace Exposure", "rule", severityutils.SeverityToSarifSeverityLevel(severityutils.Medium).String(),
					sarifutils.CreateLocation("file2", 2, 5, 3, 6, "other-snippet"),
				),
			},
			expectedAddedSastVulnerabilities: []formats.SourceCodeRow{
				{
					SeverityDetails: formats.SeverityDetails{
						Severity:         "Medium",
						SeverityNumValue: 17,
					},
					Finding: "Stack Trace Exposure",
					Location: formats.Location{
						File:        "file2",
						StartLine:   2,
						StartColumn: 5,
						EndLine:     3,
						EndColumn:   6,
						Snippet:     "other-snippet",
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			targetSastRows := xrayutils.PrepareSast([]*sarif.Run{sarifutils.CreateRunWithDummyResults(tc.targetSastResults...)})
			sourceSastRows := xrayutils.PrepareSast([]*sarif.Run{sarifutils.CreateRunWithDummyResults(tc.sourceSastResults...)})
			addedSastVulnerabilities := createNewSourceCodeRows(targetSastRows, sourceSastRows)
			assert.ElementsMatch(t, tc.expectedAddedSastVulnerabilities, addedSastVulnerabilities)
		})
	}
}

func TestDeletePreviousPullRequestMessages(t *testing.T) {
	repository := &utils.Repository{
		Params: utils.Params{
			Git: utils.Git{
				PullRequestDetails: vcsclient.PullRequestInfo{Target: vcsclient.BranchInfo{
					Repository: "repo",
					Owner:      "owner",
				}, ID: 17},
			},
		},
		OutputWriter: &outputwriter.StandardOutput{},
	}
	client := CreateMockVcsClient(t)

	testCases := []struct {
		name         string
		commentsOnPR []vcsclient.CommentInfo
		err          error
	}{
		{
			name: "Test with comment returned",
			commentsOnPR: []vcsclient.CommentInfo{
				{ID: 20, Content: outputwriter.GetBanner(outputwriter.NoVulnerabilityPrBannerSource) + "text \n table\n text text text", Created: time.Unix(3, 0)},
			},
		},
		{
			name: "Test with no comment returned",
		},
		{
			name: "Test with error returned",
			err:  errors.New("error"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test with comment returned
			client.EXPECT().ListPullRequestComments(context.Background(), "owner", "repo", 17).Return(tc.commentsOnPR, tc.err)
			client.EXPECT().DeletePullRequestComment(context.Background(), "owner", "repo", 17, 20).Return(nil).AnyTimes()
			err := utils.DeleteExistingPullRequestComments(repository, client)
			if tc.err == nil {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestDeletePreviousPullRequestReviewMessages(t *testing.T) {
	repository := &utils.Repository{
		Params: utils.Params{
			Git: utils.Git{
				PullRequestDetails: vcsclient.PullRequestInfo{Target: vcsclient.BranchInfo{
					Repository: "repo",
					Owner:      "owner",
				}, ID: 17},
			},
		},
		OutputWriter: &outputwriter.StandardOutput{},
	}
	client := CreateMockVcsClient(t)

	testCases := []struct {
		name         string
		commentsOnPR []vcsclient.CommentInfo
		err          error
	}{
		{
			name: "Test with comment returned",
			commentsOnPR: []vcsclient.CommentInfo{
				{ID: 20, Content: outputwriter.MarkdownComment(outputwriter.ReviewCommentId) + "text \n table\n text text text", Created: time.Unix(3, 0)},
			},
		},
		{
			name: "Test with no comment returned",
		},
		{
			name: "Test with error returned",
			err:  errors.New("error"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test with comment returned
			client.EXPECT().ListPullRequestReviewComments(context.Background(), "", "", 17).Return(tc.commentsOnPR, tc.err)
			client.EXPECT().DeletePullRequestReviewComments(context.Background(), "", "", 17, tc.commentsOnPR).Return(nil).AnyTimes()
			err := utils.DeleteExistingPullRequestReviewComments(repository, 17, client)
			if tc.err == nil {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestAggregateScanResults(t *testing.T) {
	scanResult1 := services.ScanResponse{
		Violations:      []services.Violation{{IssueId: "Violation 1"}},
		Vulnerabilities: []services.Vulnerability{{IssueId: "Vulnerability 1"}},
		Licenses:        []services.License{{Name: "License 1"}},
	}

	scanResult2 := services.ScanResponse{
		Violations:      []services.Violation{{IssueId: "Violation 2"}},
		Vulnerabilities: []services.Vulnerability{{IssueId: "Vulnerability 2"}},
		Licenses:        []services.License{{Name: "License 2"}},
	}

	aggregateResult := aggregateScanResults([]services.ScanResponse{scanResult1, scanResult2})
	expectedResult := services.ScanResponse{
		Violations: []services.Violation{
			{IssueId: "Violation 1"},
			{IssueId: "Violation 2"},
		},
		Vulnerabilities: []services.Vulnerability{
			{IssueId: "Vulnerability 1"},
			{IssueId: "Vulnerability 2"},
		},
		Licenses: []services.License{
			{Name: "License 1"},
			{Name: "License 2"},
		},
	}

	assert.Equal(t, expectedResult, aggregateResult)
}

// Set new logger with output redirection to a null logger. This is useful for negative tests.
// Caller is responsible to set the old log back.
func redirectLogOutputToNil() (previousLog log.Log) {
	previousLog = log.Logger
	newLog := log.NewLogger(log.ERROR, nil)
	newLog.SetOutputWriter(io.Discard)
	newLog.SetLogsWriter(io.Discard, 0)
	log.SetLogger(newLog)
	return previousLog
}
