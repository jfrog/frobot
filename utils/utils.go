package utils

import (
	"context"
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/gofrog/version"
	"github.com/jfrog/jfrog-cli-core/v2/common/commands"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/usage"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/results/conversion"
	"github.com/jfrog/jfrog-cli-security/utils/results/output"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/http/httpclient"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
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
	skipIndirectVulnerabilitiesMsg = "\n%s is an indirect dependency that will not be updated to version %s.\nFixing indirect dependencies can potentially cause conflicts with other dependencies that depend on the previous version.\nFrogbot skips this to avoid potential incompatibilities and breaking changes."
	skipBuildToolDependencyMsg     = "Skipping vulnerable package %s since it is not defined in your package descriptor file. " +
		"Update %s version to %s to fix this vulnerability."
	JfrogHomeDirEnv = "JFROG_CLI_HOME_DIR"
)

var (
	TrueVal                 = true
	FrogbotVersion          = "0.0.0"
	branchInvalidCharsRegex = regexp.MustCompile(branchNameRegex)
)

var BuildToolsDependenciesMap = map[techutils.Technology][]string{
	techutils.Go:  {"github.com/golang/go"},
	techutils.Pip: {"pip", "setuptools", "wheel"},
}

type ErrUnsupportedFix struct {
	PackageName  string
	FixedVersion string
	ErrorType    UnsupportedErrorType
}

type ErrNothingToCommit struct {
	PackageName string
}

// Custom error for unsupported fixes
// Currently we hold two unsupported reasons, indirect and build tools dependencies.
func (err *ErrUnsupportedFix) Error() string {
	if err.ErrorType == IndirectDependencyFixNotSupported {
		return fmt.Sprintf(skipIndirectVulnerabilitiesMsg, err.PackageName, err.FixedVersion)
	}
	return fmt.Sprintf(skipBuildToolDependencyMsg, err.PackageName, err.PackageName, err.FixedVersion)
}

func (err *ErrNothingToCommit) Error() string {
	return fmt.Sprintf("there were no changes to commit after fixing the package '%s'.\n"+
		"Note: Frogbot currently cannot address certain vulnerabilities in some package managers, which may result in the absence of changes", err.PackageName)
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
		log.Debug(usage.ReportUsagePrefix, "Could not create usage data to report", err.Error())
		return func() {}
	}
	reporter.Report(reports...)
	return func() {
		// Ignoring errors on purpose, we don't want to confuse the user with errors on usage reporting.
		_ = reporter.WaitForResponses()
	}
}

func convertToUsageReports(commandName string, repositories RepoAggregator) (reports []usage.ReportFeature, err error) {
	if len(repositories) == 0 {
		err = fmt.Errorf("no repositories info provided")
		return
	}
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

func UploadSarifResultsToGithubSecurityTab(scanResults *results.SecurityCommandResults, repo *Repository, branch string, client vcsclient.VcsClient, hasViolationContext bool) error {
	report, err := GenerateFrogbotSarifReport(scanResults, scanResults.HasMultipleTargets(), hasViolationContext, repo.AllowedLicenses)
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

func GenerateFrogbotSarifReport(extendedResults *results.SecurityCommandResults, isMultipleRoots, hasViolationContext bool, allowedLicenses []string) (string, error) {
	convertor := conversion.NewCommandResultsConvertor(conversion.ResultConvertParams{
		IncludeVulnerabilities: true,
		HasViolationContext:    hasViolationContext,
		IsMultipleRoots:        &isMultipleRoots,
		AllowedLicenses:        allowedLicenses,
	})
	sarifReport, err := convertor.ConvertToSarif(extendedResults)
	if err != nil {
		return "", err
	}
	return output.WriteSarifResultsAsString(sarifReport, false)
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
func IsDirectDependency(impactPathList [][]formats.ComponentRow) (bool, error) {
	if len(impactPathList) == 0 {
		return false, fmt.Errorf("invalid impact path provided")
	}

	for _, impactPath := range impactPathList {
		// Impacted path always starts with the name of the project's directory and ends with the impacted package.
		// Therefore if the length of the path is less than 2 it means the dependency is a direct one
		if len(impactPath) < 3 {
			return true, nil
		}
	}
	return false, nil
}

func validateBranchName(branchName string) error {
	// Default is "" which will be replaced with default template
	if len(branchName) == 0 {
		return nil
	}
	branchNameWithoutPlaceHolders := formatStringWithPlaceHolders(branchName, "", "", "", "", true)
	if branchInvalidCharsRegex.MatchString(branchNameWithoutPlaceHolders) {
		return errors.New(branchInvalidChars)
	}
	// Prefix cannot be '-'
	if branchName[0] == '-' {
		return errors.New(branchInvalidPrefix)
	}
	if len(branchName) > branchCharsMaxLength {
		return errors.New(branchInvalidLength)
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
	return results.GetUniqueKey(
		vulnerability.ImpactedDependencyName,
		vulnerability.ImpactedDependencyVersion,
		vulnerability.IssueId,
		len(vulnerability.FixedVersions) > 0)
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
						cve.Applicability.Evidence[i].File = sarifutils.ExtractRelativePath(cve.Applicability.Evidence[i].File, wd)
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
			iac.Location.File = sarifutils.ExtractRelativePath(iac.Location.File, wd)
		}
	}
}

func convertSarifPathsInSecrets(secrets []formats.SourceCodeRow, workingDirs ...string) {
	for i := range secrets {
		secret := &secrets[i]
		for _, wd := range workingDirs {
			secret.Location.File = sarifutils.ExtractRelativePath(secret.Location.File, wd)
		}
	}
}

func convertSarifPathsInSast(sast []formats.SourceCodeRow, workingDirs ...string) {
	for i := range sast {
		sastIssue := &sast[i]
		for _, wd := range workingDirs {
			sastIssue.Location.File = sarifutils.ExtractRelativePath(sastIssue.Location.File, wd)
			for f := range sastIssue.CodeFlow {
				for l := range sastIssue.CodeFlow[f] {
					sastIssue.CodeFlow[f][l].File = sarifutils.ExtractRelativePath(sastIssue.CodeFlow[f][l].File, wd)
				}
			}
		}
	}
}

// Normalizes whitespace in text, ensuring that words are separated by a single space, and any extra whitespace is removed.
func normalizeWhitespaces(text string) string {
	return strings.Join(strings.Fields(text), " ")
}

// Converts Technology array into a string with a separator.
func techArrayToString(techsArray []techutils.Technology, separator string) (result string) {
	if len(techsArray) == 0 {
		return ""
	}
	if len(techsArray) < 2 {
		return techsArray[0].ToFormal()
	}
	var techString []string
	for _, tech := range techsArray {
		techString = append(techString, tech.ToFormal())
	}
	return strings.Join(techString, separator)
}

type UrlAccessChecker struct {
	connected bool
	waitGroup sync.WaitGroup
	url       string
}

// CheckConnection checks if the url is accessible in a separate goroutine not to block the main thread
func CheckConnection(url string) *UrlAccessChecker {
	checker := &UrlAccessChecker{url: url}

	checker.waitGroup.Add(1)
	go func() {
		defer checker.waitGroup.Done()
		checker.connected = isUrlAccessible(url)
	}()

	return checker
}

// IsConnected checks if the URL is accessible, waits for the connection check goroutine to finish
func (ic *UrlAccessChecker) IsConnected() bool {
	ic.waitGroup.Wait()
	return ic.connected
}

// isUrlAccessible Checks if the url is accessible
func isUrlAccessible(url string) bool {
	// Build client
	client, err := httpclient.ClientBuilder().Build()
	if err != nil {
		log.Debug(fmt.Sprintf("Can't check access to '%s', build client:\n%s", url, err.Error()))
		return false
	}
	// Send HEAD request to check if the url is accessible
	req, err := http.NewRequest(http.MethodHead, url, nil)
	if errorutils.CheckError(err) != nil {
		log.Debug(fmt.Sprintf("Can't check access to '%s', error while building request:\n%s", url, err.Error()))
		return false
	}
	log.Debug(fmt.Sprintf("Sending HTTP %s request to: '%s'", req.Method, req.URL))
	resp, err := client.GetClient().Do(req)
	if errorutils.CheckError(err) != nil {
		log.Debug(fmt.Sprintf("Can't check access to '%s', error while sending request:\n%s", url, err.Error()))
		return false
	}
	return resp != nil && resp.StatusCode == http.StatusOK
}

// This function checks if partial results are allowed by the user. If so instead of returning an error we log the error and continue as if we didn't have an error
func CreateErrorIfPartialResultsDisabled(allowPartial bool, messageForLog string, err error) error {
	if allowPartial {
		log.Warn(messageForLog)
		return nil
	}
	return err
}
