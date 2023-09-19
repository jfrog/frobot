package utils

import (
	"context"
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/gofrog/version"
	"github.com/jfrog/jfrog-cli-core/v2/common/commands"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/usage"
	"github.com/jfrog/jfrog-cli-core/v2/xray/commands/audit"
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
	xrayutils "github.com/jfrog/jfrog-cli-core/v2/xray/utils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/owenrumney/go-sarif/v2/sarif"
)

const (
	ScanPullRequest          = "scan-pull-request"
	ScanAllPullRequests      = "scan-all-pull-requests"
	ScanRepository           = "scan-repository"
	ScanMultipleRepositories = "scan-multiple-repositories"
	RootDir                  = "."
	branchNameRegex          = `[~^:?\\\[\]@{}*]`

	// Branch validation error messages
	branchInvalidChars             = "branch name cannot contain the following chars  ~, ^, :, ?, *, [, ], @, {, }"
	branchInvalidPrefix            = "branch name cannot start with '-' "
	branchCharsMaxLength           = 255
	branchInvalidLength            = "branch name length exceeded " + string(rune(branchCharsMaxLength)) + " chars"
	invalidBranchTemplate          = "branch template must contain " + BranchHashPlaceHolder + " placeholder "
	skipIndirectVulnerabilitiesMsg = "\n%s is an indirect dependency that will not be updated to version %s.\nFixing indirect dependencies can potentially cause conflicts with other dependencies that depend on the previous version.\nFrogbot skips this to avoid potential incompatibilities and breaking changes."
	skipBuildToolDependencyMsg     = "Skipping vulnerable package %s since it is not defined in your package descriptor file. " +
		"Update %s version to %s to fix this vulnerability."
	JfrogHomeDirEnv = "JFROG_CLI_HOME_DIR"

	// Sarif run output tool annotator
	sarifToolName = "JFrog Frogbot"
	sarifToolUrl  = "https://github.com/jfrog/frogbot"
)

var (
	TrueVal                 = true
	FrogbotVersion          = "0.0.0"
	branchInvalidCharsRegex = regexp.MustCompile(branchNameRegex)
)

var BuildToolsDependenciesMap = map[coreutils.Technology][]string{
	coreutils.Go:  {"github.com/golang/go"},
	coreutils.Pip: {"pip", "setuptools", "wheel"},
}

type ErrUnsupportedFix struct {
	PackageName  string
	FixedVersion string
	ErrorType    UnsupportedErrorType
}

// Custom error for unsupported fixes
// Currently we hold two unsupported reasons, indirect and build tools dependencies.
func (err *ErrUnsupportedFix) Error() string {
	if err.ErrorType == IndirectDependencyFixNotSupported {
		return fmt.Sprintf(skipIndirectVulnerabilitiesMsg, err.PackageName, err.FixedVersion)
	}
	return fmt.Sprintf(skipBuildToolDependencyMsg, err.PackageName, err.PackageName, err.FixedVersion)
}

// VulnerabilityDetails serves as a container for essential information regarding a vulnerability that is going to be addressed and resolved
type VulnerabilityDetails struct {
	formats.VulnerabilityOrViolationRow
	// Suggested fix version
	SuggestedFixedVersion string
	// States whether the dependency is direct or transitive
	IsDirectDependency bool
	// Cves as a list of string
	Cves []string
}

func NewVulnerabilityDetails(vulnerability formats.VulnerabilityOrViolationRow, fixVersion string) *VulnerabilityDetails {
	vulnDetails := &VulnerabilityDetails{
		VulnerabilityOrViolationRow: vulnerability,
		SuggestedFixedVersion:       fixVersion,
	}
	vulnDetails.SetCves(vulnerability.Cves)
	return vulnDetails
}

func (vd *VulnerabilityDetails) SetIsDirectDependency(isDirectDependency bool) {
	vd.IsDirectDependency = isDirectDependency
}

func (vd *VulnerabilityDetails) SetCves(cves []formats.CveRow) {
	for _, cve := range cves {
		vd.Cves = append(vd.Cves, cve.Id)
	}
}

func (vd *VulnerabilityDetails) UpdateFixVersionIfMax(fixVersion string) {
	// Update vd.FixVersion as the maximum version if found a new version that is greater than the previous maximum version.
	if vd.SuggestedFixedVersion == "" || version.NewVersion(vd.SuggestedFixedVersion).Compare(fixVersion) > 0 {
		vd.SuggestedFixedVersion = fixVersion
	}
}

func ExtractVulnerabilitiesDetailsToRows(vulnDetails []*VulnerabilityDetails) []formats.VulnerabilityOrViolationRow {
	var rows []formats.VulnerabilityOrViolationRow
	for _, vuln := range vulnDetails {
		rows = append(rows, vuln.VulnerabilityOrViolationRow)
	}
	return rows
}

type ErrMissingEnv struct {
	VariableName string
}

func (e *ErrMissingEnv) Error() string {
	return fmt.Sprintf("'%s' environment variable is missing", e.VariableName)
}

// IsMissingEnvErr returns true if err is a type of ErrMissingEnv, otherwise false
func (e *ErrMissingEnv) IsMissingEnvErr(err error) bool {
	return errors.As(err, &e)
}

type ErrMissingConfig struct {
	missingReason string
}

func (e *ErrMissingConfig) Error() string {
	return fmt.Sprintf("config file is missing: %s", e.missingReason)
}

func Chdir(dir string) (cbk func() error, err error) {
	wd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	if err = os.Chdir(dir); err != nil {
		return nil, fmt.Errorf("could not change dir to: %s\n%s", dir, err.Error())
	}
	return func() error { return os.Chdir(wd) }, err
}

func ReportUsageOnCommand(commandName string, serverDetails *config.ServerDetails, repositories RepoAggregator) func() {
	reporter := usage.NewUsageReporter(productId, serverDetails)
	reports, err := convertToUsageReports(commandName, repositories)
	if err != nil {
		log.Debug(usage.ReportUsagePrefix, "Could not create usage data to report")
	}
	reporter.Report(reports...)
	return func() {
		if err = reporter.WaitForResponses(); err != nil {
			log.Debug(err.Error())
		}
	}
}

func convertToUsageReports(commandName string, repositories RepoAggregator) (reports []usage.ReportFeature, err error) {
	for _, repository := range repositories {
		// Report one entry for each repository as client
		if clientId, e := Md5Hash(repository.RepoName); e != nil {
			err = errors.Join(err, e)
		} else {
			reports = append(reports, usage.ReportFeature{
				FeatureId: commandName,
				ClientId:  clientId,
			})
		}
	}
	return
}

func Md5Hash(values ...string) (string, error) {
	hash := crypto.MD5.New()
	for _, ob := range values {
		_, err := fmt.Fprint(hash, ob)
		if err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// Generates MD5Hash from a VulnerabilityOrViolationRow
// The map can be returned in different order from Xray, so we need to sort the strings before hashing.
func VulnerabilityDetailsToMD5Hash(vulnerabilities ...formats.VulnerabilityOrViolationRow) (string, error) {
	hash := crypto.MD5.New()
	var keys []string
	for _, vuln := range vulnerabilities {
		keys = append(keys, GetVulnerabiltiesUniqueID(vuln))
	}
	sort.Strings(keys)
	for key, value := range keys {
		if _, err := fmt.Fprint(hash, key, value); err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func UploadSarifResultsToGithubSecurityTab(scanResults *audit.Results, repo *Repository, branch string, client vcsclient.VcsClient) error {
	report, err := GenerateFrogbotSarifReport(scanResults.ExtendedScanResults, scanResults.IsMultipleRootProject)
	if err != nil {
		return err
	}
	_, err = client.UploadCodeScanning(context.Background(), repo.RepoOwner, repo.RepoName, branch, report)
	if err != nil {
		return fmt.Errorf("upload code scanning for %s branch failed with: %s", branch, err.Error())
	}
	log.Info("The complete scanning results have been uploaded to your Code Scanning alerts view")
	return nil
}

func prepareRunsForGithubReport(runs []*sarif.Run) {
	for _, run := range runs {
		run.Tool.Driver.Name = sarifToolName
		run.Tool.Driver.WithInformationURI(sarifToolUrl)
		// Remove results without locations
		results := []*sarif.Result{}
		for _, result := range run.Results {
			if len(result.Locations) == 0 {
				continue
			}
			results = append(results, result)
		}
		run.Results = results
	}
	convertToRelativePath(runs)
}

func convertToRelativePath(runs []*sarif.Run) {
	for _, run := range runs {
		for _, result := range run.Results {
			for _, location := range result.Locations {
				xrayutils.SetLocationFileName(location, xrayutils.GetRelativeLocationFileName(location, run.Invocations))
			}
			for _, flows := range result.CodeFlows {
				for _, flow := range flows.ThreadFlows {
					for _, location := range flow.Locations {
						xrayutils.SetLocationFileName(location.Location, xrayutils.GetRelativeLocationFileName(location.Location, run.Invocations))
					}
				}
			}
		}
	}
}

func GenerateFrogbotSarifReport(extendedResults *xrayutils.ExtendedScanResults, isMultipleRoots bool) (string, error) {
	prepareRunsForGithubReport(extendedResults.ApplicabilityScanResults)
	prepareRunsForGithubReport(extendedResults.IacScanResults)
	prepareRunsForGithubReport(extendedResults.SecretsScanResults)
	prepareRunsForGithubReport(extendedResults.SastScanResults)
	// Generate report from the data
	return xrayutils.GenerateSarifContentFromResults(extendedResults, isMultipleRoots, false, true)
}

func DownloadRepoToTempDir(client vcsclient.VcsClient, repoOwner, repoName, branch string) (wd string, cleanup func() error, err error) {
	wd, err = fileutils.CreateTempDir()
	if err != nil {
		return
	}
	cleanup = func() error {
		return fileutils.RemoveTempDir(wd)
	}
	log.Debug(fmt.Sprintf("Downloading <%s/%s/%s> to: '%s'", repoOwner, repoName, branch, wd))
	if err = client.DownloadRepository(context.Background(), repoOwner, repoName, branch, wd); err != nil {
		err = fmt.Errorf("failed to download branch: <%s/%s/%s> with error: %s", repoOwner, repoName, branch, err.Error())
		return
	}
	log.Debug("Repository download completed")
	return
}

func ValidateSingleRepoConfiguration(configAggregator *RepoAggregator) error {
	// Multi repository configuration is supported only in the scanallpullrequests and scanmultiplerepositories commands.
	if len(*configAggregator) > 1 {
		return errors.New(errUnsupportedMultiRepo)
	}
	return nil
}

// GetRelativeWd receive a base working directory along with a full path containing the base working directory, and the relative part is returned without the base prefix.
func GetRelativeWd(fullPathWd, baseWd string) string {
	fullPathWd = strings.TrimSuffix(fullPathWd, string(os.PathSeparator))
	if fullPathWd == baseWd {
		return ""
	}

	return strings.TrimPrefix(fullPathWd, baseWd+string(os.PathSeparator))
}

// The impact graph of direct dependencies consists of only two elements.
func IsDirectDependency(impactPath [][]formats.ComponentRow) (bool, error) {
	if len(impactPath) == 0 {
		return false, fmt.Errorf("invalid impact path provided")
	}
	return len(impactPath[0]) < 3, nil
}

func validateBranchName(branchName string) error {
	// Default is "" which will be replaced with default template
	if len(branchName) == 0 {
		return nil
	}
	branchNameWithoutPlaceHolders := formatStringWithPlaceHolders(branchName, "", "", "", true)
	if branchInvalidCharsRegex.MatchString(branchNameWithoutPlaceHolders) {
		return fmt.Errorf(branchInvalidChars)
	}
	// Prefix cannot be '-'
	if branchName[0] == '-' {
		return fmt.Errorf(branchInvalidPrefix)
	}
	if len(branchName) > branchCharsMaxLength {
		return fmt.Errorf(branchInvalidLength)
	}
	if !strings.Contains(branchName, BranchHashPlaceHolder) {
		return fmt.Errorf(invalidBranchTemplate)
	}
	return nil
}

func BuildServerConfigFile(server *config.ServerDetails) (previousJFrogHomeDir, currentJFrogHomeDir string, err error) {
	// Create temp dir to store server config inside
	currentJFrogHomeDir, err = fileutils.CreateTempDir()
	if err != nil {
		return
	}
	// Save current JFrog Home dir
	previousJFrogHomeDir = os.Getenv(JfrogHomeDirEnv)
	// Set the temp dir as the JFrog Home dir
	if err = os.Setenv(JfrogHomeDirEnv, currentJFrogHomeDir); err != nil {
		return
	}
	cc := commands.NewConfigCommand(commands.AddOrEdit, "frogbot").SetDetails(server)
	err = cc.Run()
	return
}

func GetVulnerabiltiesUniqueID(vulnerability formats.VulnerabilityOrViolationRow) string {
	return xrayutils.GetUniqueKey(
		vulnerability.ImpactedDependencyName,
		vulnerability.ImpactedDependencyVersion,
		vulnerability.IssueId,
		len(vulnerability.FixedVersions) > 0)
}

func GetSortedPullRequestComments(client vcsclient.VcsClient, repoOwner, repoName string, prID int) ([]vcsclient.CommentInfo, error) {
	pullRequestsComments, err := client.ListPullRequestComments(context.Background(), repoOwner, repoName, prID)
	if err != nil {
		return nil, err
	}
	// Sort the comment according to time created, the newest comment should be the first one.
	sort.Slice(pullRequestsComments, func(i, j int) bool {
		return pullRequestsComments[i].Created.After(pullRequestsComments[j].Created)
	})
	return pullRequestsComments, nil
}

func ConvertSarifPathsToRelative(issues *IssuesCollection, workingDirs ...string) {
	convertSarifPathsInCveApplicability(issues.Vulnerabilities, workingDirs...)
	convertSarifPathsInIacs(issues.Iacs, workingDirs...)
	convertSarifPathsInSecrets(issues.Secrets, workingDirs...)
	convertSarifPathsInSast(issues.Sast, workingDirs...)
}

func convertSarifPathsInCveApplicability(vulnerabilities []formats.VulnerabilityOrViolationRow, workingDirs ...string) {
	for _, row := range vulnerabilities {
		for _, cve := range row.Cves {
			if cve.Applicability != nil {
				for i := range cve.Applicability.Evidence {
					for _, wd := range workingDirs {
						cve.Applicability.Evidence[i].File = xrayutils.ExtractRelativePath(cve.Applicability.Evidence[i].File, wd)
					}
				}
			}
		}
	}
}

func convertSarifPathsInIacs(iacs []formats.SourceCodeRow, workingDirs ...string) {
	for i := range iacs {
		iac := &iacs[i]
		for _, wd := range workingDirs {
			iac.Location.File = xrayutils.ExtractRelativePath(iac.Location.File, wd)
		}
	}
}

func convertSarifPathsInSecrets(secrets []formats.SourceCodeRow, workingDirs ...string) {
	for i := range secrets {
		secret := &secrets[i]
		for _, wd := range workingDirs {
			secret.Location.File = xrayutils.ExtractRelativePath(secret.Location.File, wd)
		}
	}
}

func convertSarifPathsInSast(sast []formats.SourceCodeRow, workingDirs ...string) {
	for i := range sast {
		sastIssue := &sast[i]
		for _, wd := range workingDirs {
			sastIssue.Location.File = xrayutils.ExtractRelativePath(sastIssue.Location.File, wd)
			for f := range sastIssue.CodeFlow {
				for l := range sastIssue.CodeFlow[f] {
					sastIssue.CodeFlow[f][l].File = xrayutils.ExtractRelativePath(sastIssue.CodeFlow[f][l].File, wd)
				}
			}
		}
	}
}
