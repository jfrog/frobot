package utils

import (
	"context"
	"errors"
	"fmt"
	"gopkg.in/yaml.v2"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-cli-security/utils/xsc"
	"github.com/jfrog/jfrog-client-go/xsc/services"
	"golang.org/x/exp/slices"

	"github.com/jfrog/frogbot/v2/utils/outputwriter"
	securityutils "github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"

	"github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	coreconfig "github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

const (
	frogbotConfigDir  = ".frogbot"
	FrogbotConfigFile = "frogbot-config.yml"
)

var (
	errFrogbotConfigNotFound = fmt.Errorf("%s wasn't found in the Frogbot directory and its subdirectories. Assuming all the configuration is stored as environment variables", FrogbotConfigFile)
	// Possible Config file path's to Frogbot Management repository
	osFrogbotConfigPath = filepath.Join(frogbotConfigDir, FrogbotConfigFile)
)

type FrogbotDetails struct {
	XrayVersion   string
	XscVersion    string
	Repositories  RepoAggregator
	ServerDetails *coreconfig.ServerDetails
	GitClient     vcsclient.VcsClient
	ReleasesRepo  string
}

type RepoAggregator []Repository

// NewRepoAggregator returns an initialized RepoAggregator with an empty repository
func newRepoAggregator() RepoAggregator {
	return RepoAggregator{{Params: Params{Scan: Scan{Projects: []Project{{}}}}}}
}

type Repository struct {
	Params       `yaml:"params,omitempty"`
	OutputWriter outputwriter.OutputWriter
	Server       coreconfig.ServerDetails
}

func (r *Repository) setOutputWriterDetails() {
	r.OutputWriter = outputwriter.GetCompatibleOutputWriter(r.Params.GitProvider)
	r.OutputWriter.SetAvoidExtraMessages(r.Params.AvoidExtraMessages)
	r.OutputWriter.SetPullRequestCommentTitle(r.Params.PullRequestCommentTitle)
}

type Params struct {
	Scan          `yaml:"scan,omitempty"`
	Git           `yaml:"git,omitempty"`
	JFrogPlatform `yaml:"jfrogPlatform,omitempty"`
}

func (p *Params) setDefaultsIfNeeded(gitParamsFromEnv *Git, commandName string) error {
	if err := p.Git.setDefaultsIfNeeded(gitParamsFromEnv, commandName); err != nil {
		return err
	}
	if err := p.JFrogPlatform.setDefaultsIfNeeded(); err != nil {
		return err
	}
	return p.Scan.setDefaultsIfNeeded()
}

type Project struct {
	InstallCommand      string   `yaml:"installCommand,omitempty"`
	PipRequirementsFile string   `yaml:"pipRequirementsFile,omitempty"`
	WorkingDirs         []string `yaml:"workingDirs,omitempty"`
	PathExclusions      []string `yaml:"pathExclusions,omitempty"`
	UseWrapper          *bool    `yaml:"useWrapper,omitempty"`
	MaxPnpmTreeDepth    string   `yaml:"maxPnpmTreeDepth,omitempty"`
	DepsRepo            string   `yaml:"repository,omitempty"`
	InstallCommandName  string
	InstallCommandArgs  []string
	IsRecursiveScan     bool
}

func (p *Project) setDefaultsIfNeeded() error {
	if len(p.WorkingDirs) == 0 {
		workingDirs, _ := readArrayParamFromEnv(WorkingDirectoryEnv, WatchesDelimiter)
		if len(workingDirs) == 0 {
			// If no working directories are provided, and none exist in the environment variable, we designate the project's root directory as our sole working directory.
			// We then execute a recursive scan across the entire project, commencing from the root.
			workingDirs = []string{RootDir}
			p.IsRecursiveScan = true
		}
		p.WorkingDirs = append(p.WorkingDirs, workingDirs...)
	}
	if len(p.PathExclusions) == 0 {
		if p.PathExclusions, _ = readArrayParamFromEnv(PathExclusionsEnv, ";"); len(p.PathExclusions) == 0 {
			p.PathExclusions = securityutils.DefaultScaExcludePatterns
		}
	}
	if p.UseWrapper == nil {
		useWrapper, err := getBoolEnv(UseWrapperEnv, true)
		if err != nil {
			return err
		}
		p.UseWrapper = &useWrapper
	}
	if p.InstallCommand == "" {
		p.InstallCommand = getTrimmedEnv(InstallCommandEnv)
	}
	if p.InstallCommand != "" {
		setProjectInstallCommand(p.InstallCommand, p)
	}
	if p.PipRequirementsFile == "" {
		p.PipRequirementsFile = getTrimmedEnv(RequirementsFileEnv)
	}
	if p.DepsRepo == "" {
		p.DepsRepo = getTrimmedEnv(DepsRepoEnv)
	}
	if p.MaxPnpmTreeDepth == "" {
		p.MaxPnpmTreeDepth = getTrimmedEnv(MaxPnpmTreeDepthEnv)
	}

	return nil
}

func (p *Project) GetTechFromInstallCmdIfExists() []string {
	var technologies []string
	if p.InstallCommandName != "" {
		if !slices.Contains(techutils.AllTechnologiesStrings, p.InstallCommandName) {
			log.Warn(fmt.Sprintf("The technology ‘%s’ was inferred from the provided install command but is not listed among the supported technologies. Please provide an install command for one of the following supported technologies: %s", p.InstallCommandName, techutils.AllTechnologiesStrings))
			return technologies
		}
		technologies = append(technologies, p.InstallCommandName)
		if strings.ToLower(p.InstallCommandName) == "dotnet" {
			technologies = append(technologies, "nuget")
		}
	}
	return technologies
}

type Scan struct {
	IncludeAllVulnerabilities       bool      `yaml:"includeAllVulnerabilities,omitempty"`
	FixableOnly                     bool      `yaml:"fixableOnly,omitempty"`
	DetectionOnly                   bool      `yaml:"skipAutoFix,omitempty"`
	FailOnSecurityIssues            *bool     `yaml:"failOnSecurityIssues,omitempty"`
	AvoidPreviousPrCommentsDeletion bool      `yaml:"avoidPreviousPrCommentsDeletion,omitempty"`
	MinSeverity                     string    `yaml:"minSeverity,omitempty"`
	DisableJas                      bool      `yaml:"disableJas,omitempty"`
	AddPrCommentOnSuccess           bool      `yaml:"addPrCommentOnSuccess,omitempty"`
	AllowedLicenses                 []string  `yaml:"allowedLicenses,omitempty"`
	Projects                        []Project `yaml:"projects,omitempty"`
	EmailDetails                    `yaml:",inline"`
	ConfigProfile                   *services.ConfigProfile
	SkipAutoInstall                 bool
	AllowPartialResults             bool
}

type EmailDetails struct {
	SmtpServer     string
	SmtpPort       string
	SmtpUser       string
	SmtpPassword   string
	EmailReceivers []string `yaml:"emailReceivers,omitempty"`
}

func (s *Scan) SetEmailDetails() error {
	smtpServerAndPort := getTrimmedEnv(SmtpServerEnv)
	if smtpServerAndPort == "" {
		return nil
	}
	splittedServerAndPort := strings.Split(smtpServerAndPort, ":")
	if len(splittedServerAndPort) < 2 {
		return fmt.Errorf("failed while setting your email details. Could not extract the smtp server and its port from the %s environment variable. Expected format: `smtp.server.com:port`, received: %s", SmtpServerEnv, smtpServerAndPort)
	}
	s.SmtpServer = splittedServerAndPort[0]
	s.SmtpPort = splittedServerAndPort[1]
	s.SmtpUser = getTrimmedEnv(SmtpUserEnv)
	s.SmtpPassword = getTrimmedEnv(SmtpPasswordEnv)
	if s.SmtpUser == "" {
		return fmt.Errorf("failed while setting your email details. SMTP username is expected, but the %s environment variable is empty", SmtpUserEnv)
	}
	if s.SmtpPassword == "" {
		return fmt.Errorf("failed while setting your email details. SMTP password is expected, but the %s environment variable is empty", SmtpPasswordEnv)
	}
	if len(s.EmailReceivers) == 0 {
		if emailReceiversEnv := getTrimmedEnv(EmailReceiversEnv); emailReceiversEnv != "" {
			s.EmailReceivers = strings.Split(emailReceiversEnv, ",")
		}
	}
	return nil
}

func (s *Scan) setDefaultsIfNeeded() (err error) {
	e := &ErrMissingEnv{}
	if !s.IncludeAllVulnerabilities {
		if s.IncludeAllVulnerabilities, err = getBoolEnv(IncludeAllVulnerabilitiesEnv, false); err != nil {
			return
		}
	}
	if !s.AvoidPreviousPrCommentsDeletion {
		if s.AvoidPreviousPrCommentsDeletion, err = getBoolEnv(AvoidPreviousPrCommentsDeletionEnv, false); err != nil {
			return
		}
	}
	if !s.FixableOnly {
		if s.FixableOnly, err = getBoolEnv(FixableOnlyEnv, false); err != nil {
			return
		}
	}
	if !s.DisableJas {
		if s.DisableJas, err = getBoolEnv(DisableJasEnv, false); err != nil {
			return
		}
	}
	if !s.AddPrCommentOnSuccess {
		if s.AddPrCommentOnSuccess, err = getBoolEnv(AddPrCommentOnSuccessEnv, true); err != nil {
			return
		}
	}
	if !s.DetectionOnly {
		if s.DetectionOnly, err = getBoolEnv(DetectionOnlyEnv, false); err != nil {
			return
		}
	}
	if s.FailOnSecurityIssues == nil {
		var failOnSecurityIssues bool
		if failOnSecurityIssues, err = getBoolEnv(FailOnSecurityIssuesEnv, true); err != nil {
			return
		}
		s.FailOnSecurityIssues = &failOnSecurityIssues
	}
	if s.MinSeverity == "" {
		if err = readParamFromEnv(MinSeverityEnv, &s.MinSeverity); err != nil && !e.IsMissingEnvErr(err) {
			return
		}
	}
	if s.MinSeverity != "" {
		var severity severityutils.Severity
		if severity, err = severityutils.ParseSeverity(s.MinSeverity, false); err != nil {
			return
		}
		s.MinSeverity = severity.String()
	}
	if !s.SkipAutoInstall {
		if s.SkipAutoInstall, err = getBoolEnv(SkipAutoInstallEnv, false); err != nil {
			return
		}
	}
	if len(s.Projects) == 0 {
		s.Projects = append(s.Projects, Project{})
	}
	if len(s.AllowedLicenses) == 0 {
		if s.AllowedLicenses, err = readArrayParamFromEnv(AllowedLicensesEnv, ","); err != nil && !e.IsMissingEnvErr(err) {
			return
		}
	}
	if !s.AllowPartialResults {
		if s.AllowPartialResults, err = getBoolEnv(AllowPartialResultsEnv, false); err != nil {
			return
		}
	}
	for i := range s.Projects {
		if err = s.Projects[i].setDefaultsIfNeeded(); err != nil {
			return
		}
	}
	err = s.SetEmailDetails()
	return
}

type JFrogPlatform struct {
	XrayVersion            string
	XscVersion             string
	Watches                []string `yaml:"watches,omitempty"`
	IncludeVulnerabilities bool     `yaml:"includeVulnerabilities,omitempty"`
	JFrogProjectKey        string   `yaml:"jfrogProjectKey,omitempty"`
}

func (jp *JFrogPlatform) setDefaultsIfNeeded() (err error) {
	e := &ErrMissingEnv{}
	if len(jp.Watches) == 0 {
		if jp.Watches, err = readArrayParamFromEnv(jfrogWatchesEnv, WatchesDelimiter); err != nil && !e.IsMissingEnvErr(err) {
			return
		}
	}
	if jp.JFrogProjectKey == "" {
		if err = readParamFromEnv(jfrogProjectEnv, &jp.JFrogProjectKey); err != nil && !e.IsMissingEnvErr(err) {
			return
		}
		// We don't want to return an error from this function if the error is of type ErrMissingEnv because JFrogPlatform environment variables are not mandatory.
		err = nil
	}
	if !jp.IncludeVulnerabilities {
		if jp.IncludeVulnerabilities, err = getBoolEnv(IncludeVulnerabilitiesEnv, false); err != nil {
			return
		}
	}
	return
}

type Git struct {
	GitProvider vcsutils.VcsProvider
	vcsclient.VcsInfo
	UseMostCommonAncestorAsTarget bool `yaml:"useMostCommonAncestorAsTarget,omitempty"`
	RepoOwner                     string
	RepoName                      string   `yaml:"repoName,omitempty"`
	Branches                      []string `yaml:"branches,omitempty"`
	BranchNameTemplate            string   `yaml:"branchNameTemplate,omitempty"`
	CommitMessageTemplate         string   `yaml:"commitMessageTemplate,omitempty"`
	PullRequestTitleTemplate      string   `yaml:"pullRequestTitleTemplate,omitempty"`
	PullRequestCommentTitle       string   `yaml:"pullRequestCommentTitle,omitempty"`
	PullRequestSecretComments     bool     `yaml:"pullRequestSecretComments,omitempty"`
	AvoidExtraMessages            bool     `yaml:"avoidExtraMessages,omitempty"`
	EmailAuthor                   string   `yaml:"emailAuthor,omitempty"`
	AggregateFixes                bool     `yaml:"aggregateFixes,omitempty"`
	PullRequestDetails            vcsclient.PullRequestInfo
	RepositoryCloneUrl            string
	UseLocalRepository            bool
}

func (g *Git) GetRepositoryHttpsCloneUrl(gitClient vcsclient.VcsClient) (string, error) {
	if g.RepositoryCloneUrl != "" {
		return g.RepositoryCloneUrl, nil
	}
	// If the repository clone URL is not cached, we fetch it from the VCS provider
	repositoryInfo, err := gitClient.GetRepositoryInfo(context.Background(), g.RepoOwner, g.RepoName)
	if err != nil {
		return "", fmt.Errorf("failed to fetch the repository clone URL. %s", err.Error())
	}
	g.RepositoryCloneUrl = repositoryInfo.CloneInfo.HTTP
	return g.RepositoryCloneUrl, nil
}

func (g *Git) setDefaultsIfNeeded(gitParamsFromEnv *Git, commandName string) (err error) {
	g.RepoOwner = gitParamsFromEnv.RepoOwner
	g.GitProvider = gitParamsFromEnv.GitProvider
	g.VcsInfo = gitParamsFromEnv.VcsInfo
	g.PullRequestDetails = gitParamsFromEnv.PullRequestDetails
	if g.RepoName == "" {
		if gitParamsFromEnv.RepoName == "" {
			return fmt.Errorf("repository name is missing. please set the repository name in your %s file or as the %s environment variable", FrogbotConfigFile, GitRepoEnv)
		}
		g.RepoName = gitParamsFromEnv.RepoName
	}
	if g.EmailAuthor == "" {
		if g.EmailAuthor = getTrimmedEnv(GitEmailAuthorEnv); g.EmailAuthor == "" {
			g.EmailAuthor = frogbotAuthorEmail
		}
	}
	if commandName == ScanPullRequest {
		if err = g.extractScanPullRequestEnvParams(gitParamsFromEnv); err != nil {
			return
		}
	}
	if commandName == ScanRepository || commandName == ScanMultipleRepositories {
		if err = g.extractScanRepositoryEnvParams(gitParamsFromEnv); err != nil {
			return
		}
	}
	return
}

func (g *Git) extractScanPullRequestEnvParams(gitParamsFromEnv *Git) (err error) {
	// The Pull Request ID is a mandatory requirement for Frogbot to properly identify and scan the relevant pull request
	if gitParamsFromEnv.PullRequestDetails.ID == 0 {
		return errors.New("no Pull Request ID has been provided. Please configure it by using the `JF_GIT_PULL_REQUEST_ID` environment variable")
	}
	if g.PullRequestCommentTitle == "" {
		g.PullRequestCommentTitle = getTrimmedEnv(PullRequestCommentTitleEnv)
	}
	if !g.PullRequestSecretComments {
		if g.PullRequestSecretComments, err = getBoolEnv(PullRequestSecretCommentsEnv, false); err != nil {
			return
		}
	}
	if !g.UseMostCommonAncestorAsTarget {
		if g.UseMostCommonAncestorAsTarget, err = getBoolEnv(UseMostCommonAncestorAsTargetEnv, true); err != nil {
			return
		}
	}
	g.AvoidExtraMessages, err = getBoolEnv(AvoidExtraMessages, false)
	return
}

func (g *Git) extractScanRepositoryEnvParams(gitParamsFromEnv *Git) (err error) {
	// Continue to extract ScanRepository related env params
	noBranchesProvidedViaConfig := len(g.Branches) == 0
	noBranchesProvidedViaEnv := len(gitParamsFromEnv.Branches) == 0
	if noBranchesProvidedViaConfig {
		if noBranchesProvidedViaEnv {
			return errors.New("no branches were provided. Please set your branches using the `JF_GIT_BASE_BRANCH` environment variable or by configuring them in the frogbot-config.yml file")
		}
		g.Branches = gitParamsFromEnv.Branches
	}
	if g.BranchNameTemplate == "" {
		branchTemplate := getTrimmedEnv(BranchNameTemplateEnv)
		if err = validateHashPlaceHolder(branchTemplate); err != nil {
			return
		}
		g.BranchNameTemplate = branchTemplate
	}
	if g.CommitMessageTemplate == "" {
		g.CommitMessageTemplate = getTrimmedEnv(CommitMessageTemplateEnv)
	}
	if g.PullRequestTitleTemplate == "" {
		g.PullRequestTitleTemplate = getTrimmedEnv(PullRequestTitleTemplateEnv)
	}
	if !g.AggregateFixes {
		if g.AggregateFixes, err = getBoolEnv(GitAggregateFixesEnv, false); err != nil {
			return
		}
	}
	if !g.UseLocalRepository {
		if g.UseLocalRepository, err = getBoolEnv(GitUseLocalRepositoryEnv, false); err != nil {
			return
		}
	}
	return
}

func validateHashPlaceHolder(template string) error {
	if template == "" {
		return nil
	}
	if !strings.Contains(template, BranchHashPlaceHolder) {
		return fmt.Errorf("branch name template must contain %s, provided: %s", BranchHashPlaceHolder, template)
	}
	return nil
}

func GetFrogbotDetails(commandName string) (frogbotDetails *FrogbotDetails, err error) {
	// Get server and git details
	jfrogServer, err := extractJFrogCredentialsFromEnvs()
	if err != nil {
		return
	}
	xrayVersion, xscVersion, err := xsc.GetJfrogServicesVersion(jfrogServer)
	if err != nil {
		return
	}

	gitParamsFromEnv, err := extractGitParamsFromEnvs(commandName)
	if err != nil {
		return
	}

	defer func() {
		err = errors.Join(err, SanitizeEnv())
	}()

	// Build a version control client for REST API requests
	client, err := vcsclient.
		NewClientBuilder(gitParamsFromEnv.GitProvider).
		ApiEndpoint(strings.TrimSuffix(gitParamsFromEnv.APIEndpoint, "/")).
		Token(gitParamsFromEnv.Token).
		Project(gitParamsFromEnv.Project).
		Logger(log.GetLogger()).
		Username(gitParamsFromEnv.Username).
		Build()
	if err != nil {
		return
	}

	configAggregator, err := getConfigAggregator(xrayVersion, xscVersion, client, gitParamsFromEnv, jfrogServer, commandName)
	if err != nil {
		return
	}

	configProfile, repoCloneUrl, err := getConfigProfileIfExistsAndValid(xrayVersion, xscVersion, jfrogServer, client, gitParamsFromEnv)
	if err != nil {
		return
	}

	// We apply the configProfile to all received repositories. If no config profile was fetched, a nil value is passed
	// TODO This loop must be deleted when we will no longer accept multiple repositories in a single scan
	for i := range configAggregator {
		configAggregator[i].Scan.ConfigProfile = configProfile
		configAggregator[i].Git.RepositoryCloneUrl = repoCloneUrl
	}

	frogbotDetails = &FrogbotDetails{XrayVersion: xrayVersion, XscVersion: xscVersion, Repositories: configAggregator, GitClient: client, ServerDetails: jfrogServer, ReleasesRepo: os.Getenv(jfrogReleasesRepoEnv)}
	return
}

// getConfigAggregator returns a RepoAggregator based on frogbot-config.yml and environment variables.
func getConfigAggregator(xrayVersion, xscVersion string, gitClient vcsclient.VcsClient, gitParamsFromEnv *Git, jfrogServer *coreconfig.ServerDetails, commandName string) (RepoAggregator, error) {
	configFileContent, err := getConfigFileContent(gitClient, gitParamsFromEnv, commandName)
	if err != nil {
		return nil, err
	}
	if configFileContent != nil {
		log.Debug(fmt.Sprintf("The content of %s that will be used is:\n%s", FrogbotConfigFile, string(configFileContent)))
	}
	return BuildRepoAggregator(xrayVersion, xscVersion, gitClient, configFileContent, gitParamsFromEnv, jfrogServer, commandName)
}

// getConfigFileContent retrieves the content of the frogbot-config.yml file
func getConfigFileContent(gitClient vcsclient.VcsClient, gitParamsFromEnv *Git, commandName string) ([]byte, error) {
	var errMissingConfig *ErrMissingConfig

	if commandName == ScanRepository || commandName == ScanMultipleRepositories {
		configFileContent, err := ReadConfigFromFileSystem(osFrogbotConfigPath)
		if err != nil && !errors.As(err, &errMissingConfig) {
			return nil, err
		}
		if configFileContent != nil {
			return configFileContent, nil
		}
	}

	configFileContent, err := readConfigFromTarget(gitClient, gitParamsFromEnv)
	if errors.As(err, &errMissingConfig) {
		// Avoid returning an error if the frogbot-config.yml file is missing.
		// If an error occurs because the file is missing, we will create an environment variable-based configuration aggregator instead.
		return nil, nil
	}
	return configFileContent, err
}

// BuildRepoAggregator receives the content of a frogbot-config.yml file, along with the Git (built from environment variables) and ServerDetails parameters.
// Returns a RepoAggregator instance with all the defaults and necessary fields.
func BuildRepoAggregator(xrayVersion, xscVersion string, gitClient vcsclient.VcsClient, configFileContent []byte, gitParamsFromEnv *Git, server *coreconfig.ServerDetails, commandName string) (resultAggregator RepoAggregator, err error) {
	var cleanAggregator RepoAggregator
	// Unmarshal the frogbot-config.yml file if exists
	if cleanAggregator, err = unmarshalFrogbotConfigYaml(configFileContent); err != nil {
		return
	}
	for _, repository := range cleanAggregator {
		repository.Server = *server
		repository.Params.XrayVersion = xrayVersion
		repository.Params.XscVersion = xscVersion
		if err = repository.Params.setDefaultsIfNeeded(gitParamsFromEnv, commandName); err != nil {
			return
		}
		repository.setOutputWriterDetails()
		repository.OutputWriter.SetSizeLimit(gitClient)
		resultAggregator = append(resultAggregator, repository)
	}

	return
}

// unmarshalFrogbotConfigYaml uses the yaml.Unmarshaler interface to parse the yamlContent.
// If there is no config file, the function returns a RepoAggregator with an empty repository.
func unmarshalFrogbotConfigYaml(yamlContent []byte) (result RepoAggregator, err error) {
	if len(yamlContent) == 0 {
		result = newRepoAggregator()
		return
	}
	err = yaml.Unmarshal(yamlContent, &result)
	return
}

func extractJFrogCredentialsFromEnvs() (*coreconfig.ServerDetails, error) {
	server := coreconfig.ServerDetails{}
	platformUrl := strings.TrimSuffix(getTrimmedEnv(JFrogUrlEnv), "/")
	xrUrl := strings.TrimSuffix(getTrimmedEnv(jfrogXrayUrlEnv), "/")
	rtUrl := strings.TrimSuffix(getTrimmedEnv(jfrogArtifactoryUrlEnv), "/")
	if xrUrl != "" && rtUrl != "" {
		server.XrayUrl = xrUrl + "/"
		server.ArtifactoryUrl = rtUrl + "/"
	} else {
		if platformUrl == "" {
			return nil, fmt.Errorf("%s or %s and %s environment variables are missing", JFrogUrlEnv, jfrogXrayUrlEnv, jfrogArtifactoryUrlEnv)
		}
		server.Url = platformUrl + "/"
		server.XrayUrl = platformUrl + "/xray/"
		server.ArtifactoryUrl = platformUrl + "/artifactory/"
	}

	password := getTrimmedEnv(JFrogPasswordEnv)
	user := getTrimmedEnv(JFrogUserEnv)
	if password != "" && user != "" {
		server.User = user
		server.Password = password
	} else if accessToken := getTrimmedEnv(JFrogTokenEnv); accessToken != "" {
		server.AccessToken = accessToken
	} else {
		return nil, fmt.Errorf("%s and %s or %s environment variables are missing", JFrogUserEnv, JFrogPasswordEnv, JFrogTokenEnv)
	}
	return &server, nil
}

func extractGitParamsFromEnvs(commandName string) (*Git, error) {
	e := &ErrMissingEnv{}
	var err error
	gitEnvParams := &Git{}
	// Branch & Repo names are mandatory variables.
	// Must be set in the frogbot-config.yml or as an environment variables.
	// Validation performed later
	// Set the base branch name
	var branch string
	if err = readParamFromEnv(GitBaseBranchEnv, &branch); err != nil && !e.IsMissingEnvErr(err) {
		return nil, err
	}
	if branch != "" {
		gitEnvParams.Branches = []string{branch}
	}
	// Non-mandatory Git Api Endpoint, if not set, default values will be used.
	if err = readParamFromEnv(GitApiEndpointEnv, &gitEnvParams.APIEndpoint); err != nil && !e.IsMissingEnvErr(err) {
		return nil, err
	}
	if err = verifyValidApiEndpoint(gitEnvParams.APIEndpoint); err != nil {
		return nil, err
	}
	// [Mandatory] Set the Git provider
	if gitEnvParams.GitProvider, err = extractVcsProviderFromEnv(); err != nil {
		return nil, err
	}
	// [Mandatory] Set the git repository owner name (organization)
	if err = readParamFromEnv(GitRepoOwnerEnv, &gitEnvParams.RepoOwner); err != nil {
		return nil, err
	}
	// [Mandatory] Set the access token to the git provider
	if err = readParamFromEnv(GitTokenEnv, &gitEnvParams.Token); err != nil {
		return nil, err
	}

	// [Mandatory] Set the repository name, except for multi repository.
	if err = readParamFromEnv(GitRepoEnv, &gitEnvParams.RepoName); err != nil && commandName != ScanMultipleRepositories {
		return nil, err
	}

	// Set Bitbucket Server username
	// Mandatory only for Bitbucket Server, this authentication detail is required for performing git operations.
	if err = readParamFromEnv(GitUsernameEnv, &gitEnvParams.Username); err != nil && !e.IsMissingEnvErr(err) {
		return nil, err
	}
	// Set Azure Repos Project name
	// Mandatory for Azure Repos only
	if err = readParamFromEnv(GitProjectEnv, &gitEnvParams.Project); err != nil && gitEnvParams.GitProvider == vcsutils.AzureRepos {
		return nil, err
	}
	if envPrId := getTrimmedEnv(GitPullRequestIDEnv); envPrId != "" {
		var convertedPrId int
		if convertedPrId, err = strconv.Atoi(envPrId); err != nil {
			return nil, fmt.Errorf("failed parsing %s environment variable as a number. The received environment is : %s", GitPullRequestIDEnv, envPrId)
		}
		gitEnvParams.PullRequestDetails = vcsclient.PullRequestInfo{ID: int64(convertedPrId)}
	}

	return gitEnvParams, nil
}

func verifyValidApiEndpoint(apiEndpoint string) error {
	// Empty string will resolve to default values.
	if apiEndpoint == "" {
		return nil
	}
	parsedUrl, err := url.Parse(apiEndpoint)
	if err != nil {
		return err
	}
	if parsedUrl.Scheme == "" {
		return errors.New("the given API endpoint is invalid. Please note that the API endpoint format should be provided with the 'HTTPS' protocol as a prefix")
	}
	return nil
}

func readArrayParamFromEnv(envKey, delimiter string) ([]string, error) {
	var envValue string
	var err error
	e := &ErrMissingEnv{}
	if err = readParamFromEnv(envKey, &envValue); err != nil && !e.IsMissingEnvErr(err) {
		return nil, err
	}
	if envValue == "" {
		return nil, &ErrMissingEnv{VariableName: envKey}
	}
	// Remove spaces if exists
	envValue = strings.ReplaceAll(envValue, " ", "")
	return strings.Split(envValue, delimiter), nil
}

func readParamFromEnv(envKey string, paramValue *string) error {
	*paramValue = getTrimmedEnv(envKey)
	if *paramValue == "" {
		return &ErrMissingEnv{VariableName: envKey}
	}
	return nil
}

func getTrimmedEnv(envKey string) string {
	return strings.TrimSpace(os.Getenv(envKey))
}

func extractVcsProviderFromEnv() (vcsutils.VcsProvider, error) {
	vcsProvider := getTrimmedEnv(GitProvider)
	switch vcsProvider {
	case string(GitHub):
		return vcsutils.GitHub, nil
	case string(GitLab):
		return vcsutils.GitLab, nil
	// For backward compatibility, we are accepting also "bitbucket server"
	case string(BitbucketServer), "bitbucket server":
		return vcsutils.BitbucketServer, nil
	case string(AzureRepos):
		return vcsutils.AzureRepos, nil
	}
	return 0, fmt.Errorf("%s should be one of: '%s', '%s', '%s' or '%s'", GitProvider, GitHub, GitLab, BitbucketServer, AzureRepos)
}

func SanitizeEnv() error {
	for _, env := range os.Environ() {
		if !strings.HasPrefix(env, "JF_") {
			continue
		}
		envSplit := strings.Split(env, "=")
		if err := os.Unsetenv(envSplit[0]); err != nil {
			return err
		}
	}
	return nil
}

// ReadConfigFromFileSystem looks for .frogbot/frogbot-config.yml from the given path and return its content. The path is relative and starts from the root of the project.
// If the config file is not found in the relative path, it will search in parent dirs.
func ReadConfigFromFileSystem(configRelativePath string) (configFileContent []byte, err error) {
	log.Debug("Reading config from file system. Looking for", osFrogbotConfigPath)
	fullConfigDirPath, err := filepath.Abs(configRelativePath)
	if err != nil {
		return nil, err
	}

	// Look for the frogbot-config.yml file in fullConfigPath
	exist, err := utils.IsFileExists(fullConfigDirPath, false)
	if !exist || err != nil {
		// Look for the frogbot-config.yml in fullConfigPath parents dirs
		log.Debug(FrogbotConfigFile, "wasn't found in "+fullConfigDirPath+". Searching for it in upstream directories")
		if fullConfigDirPath, err = utils.FindFileInDirAndParents(fullConfigDirPath, configRelativePath); err != nil {
			return nil, &ErrMissingConfig{errFrogbotConfigNotFound.Error()}
		}
		fullConfigDirPath = filepath.Join(fullConfigDirPath, configRelativePath)
	}

	log.Debug(FrogbotConfigFile, "found in", fullConfigDirPath)
	configFileContent, err = os.ReadFile(filepath.Clean(fullConfigDirPath))
	if err != nil {
		err = fmt.Errorf("an error occurd while reading the %s file at: %s\n%s", FrogbotConfigFile, configRelativePath, err.Error())
	}
	return
}

func setProjectInstallCommand(installCommand string, project *Project) {
	parts := strings.Fields(installCommand)
	if len(parts) > 1 {
		project.InstallCommandArgs = parts[1:]
	}
	project.InstallCommandName = parts[0]
}

func getBoolEnv(envKey string, defaultValue bool) (bool, error) {
	envValue := getTrimmedEnv(envKey)
	if envValue != "" {
		parsedEnv, err := strconv.ParseBool(envValue)
		if err != nil {
			return false, fmt.Errorf("the value of the %s environment is expected to be either TRUE or FALSE. The value received however is %s", envKey, envValue)
		}
		return parsedEnv, nil
	}

	return defaultValue, nil
}

// readConfigFromTarget reads the .frogbot/frogbot-config.yml from the target repository
func readConfigFromTarget(client vcsclient.VcsClient, gitParamsFromEnv *Git) (configContent []byte, err error) {
	// Extract repository details from Git parameters
	repoName := gitParamsFromEnv.RepoName
	repoOwner := gitParamsFromEnv.RepoOwner
	branches := gitParamsFromEnv.Branches

	if repoName == "" && repoOwner == "" {
		return
	}

	log.Debug("Attempting to download", FrogbotConfigFile, "from", repoOwner+"/"+repoName)

	var branch string
	if len(branches) == 0 {
		log.Debug(GitBaseBranchEnv, "is missing. Assuming that the", FrogbotConfigFile, "file exists on default branch")
	} else {
		// We encounter this scenario when the JF_GIT_BASE_BRANCH is defined. In this situation, we have only one branch.
		branch = branches[0]
		log.Debug("The", FrogbotConfigFile, "will be downloaded from", branch, "branch")
	}

	// Construct the path to the frogbot-config.yml file in the repository
	gitFrogbotConfigPath := fmt.Sprintf("%s/%s", frogbotConfigDir, FrogbotConfigFile)

	// Download the frogbot-config.yml file from the repository
	var statusCode int
	configContent, statusCode, err = client.DownloadFileFromRepo(context.Background(), repoOwner, repoName, branch, gitFrogbotConfigPath)

	// Handle different HTTP status codes
	switch statusCode {
	case http.StatusOK:
		log.Info(fmt.Sprintf("Successfully downloaded %s file from <%s/%s/%s>", FrogbotConfigFile, repoOwner, repoName, branch))
	case http.StatusNotFound:
		log.Debug(fmt.Sprintf("The %s file wasn't recognized in <%s/%s>", gitFrogbotConfigPath, repoOwner, repoName))
		// If .frogbot/frogbot-config.yml isn't found, return an ErrMissingConfig
		configContent = nil
		err = &ErrMissingConfig{errFrogbotConfigNotFound.Error()}
	case http.StatusUnauthorized:
		log.Warn("Your credentials seem to be invalid. If you are using an on-premises Git provider, please set the API endpoint of your Git provider using the 'JF_GIT_API_ENDPOINT' environment variable (example: 'https://gitlab.example.com'). Additionally, make sure that the provided credentials have the required Git permissions.")
	}
	return
}

// This function attempts to fetch a config profile if JF_USE_CONFIG_PROFILE is set to true.
// If we need to use a profile, we first try to get the profile by name that can be provided through JF_CONFIG_PROFILE. If name is provided but profile doesn't exist we return an error.
// If we need to use a profile, but name is not provided, we check if there is a config profile associated to the repo URL.
// When a profile is found we verify several conditions on it.
// If a profile was requested but not found by url nor by name we return an error.
func getConfigProfileIfExistsAndValid(xrayVersion, xscVersion string, jfrogServer *coreconfig.ServerDetails, gitClient vcsclient.VcsClient, gitParams *Git) (configProfile *services.ConfigProfile, repoCloneUrl string, err error) {
	var useConfigProfile bool
	if useConfigProfile, err = getBoolEnv(JfrogUseConfigProfileEnv, false); err != nil || !useConfigProfile {
		log.Debug(fmt.Sprintf("Configuration Profile usage is disabled. All configurations will be derived from environment variables and files.\nTo enable a Configuration Profile, please set %s to TRUE", JfrogUseConfigProfileEnv))
		return
	}
	// Attempt to get the config profile by profile's name
	profileName := getTrimmedEnv(JfrogConfigProfileEnv)
	if profileName != "" {
		log.Debug(fmt.Sprintf("Configuration profile was requested. Searching profile by provided name '%s'", profileName))
		if configProfile, err = xsc.GetConfigProfileByName(xrayVersion, xscVersion, jfrogServer, profileName); err != nil || configProfile == nil {
			return
		}
		err = verifyConfigProfileValidity(configProfile)
		return
	}
	// Getting repository's url in order to get repository HTTP url
	if repoCloneUrl, err = gitParams.GetRepositoryHttpsCloneUrl(gitClient); err != nil {
		return
	}
	// Attempt to get a config profile associated with the repo URL
	log.Debug(fmt.Sprintf("Configuration profile was requested. Searching profile associated to repository '%s'", jfrogServer.Url))
	if configProfile, err = xsc.GetConfigProfileByUrl(xrayVersion, jfrogServer, repoCloneUrl); err != nil || configProfile == nil {
		return
	}
	err = verifyConfigProfileValidity(configProfile)
	return
}

func verifyConfigProfileValidity(configProfile *services.ConfigProfile) (err error) {
	// Currently, only a single Module that represents the entire project is supported
	if len(configProfile.Modules) != 1 {
		err = fmt.Errorf("more than one module was found '%s' profile. Frogbot currently supports only one module per config profile", configProfile.ProfileName)
		return
	}
	if configProfile.Modules[0].PathFromRoot != "." {
		err = fmt.Errorf("module '%s' in profile '%s' contains the following path from root: '%s'. Frogbot currently supports only a single module with a '.' path from root", configProfile.Modules[0].ModuleName, configProfile.ProfileName, configProfile.Modules[0].PathFromRoot)
		return
	}
	log.Info(fmt.Sprintf("Using Config profile '%s'. jfrog-apps-config will be ignored if exists", configProfile.ProfileName))
	return
}
