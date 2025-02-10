package utils

import (
	"github.com/jfrog/frogbot/v2/utils/outputwriter"
)

type vcsProvider string
type ciProvider string

const (
	// Errors
	errUnsupportedMultiRepo = "multi repository configuration isn't supported. Only one repository configuration is allowed"

	// VCS providers params
	GitHub          vcsProvider = "github"
	GitLab          vcsProvider = "gitlab"
	BitbucketServer vcsProvider = "bitbucketServer"
	AzureRepos      vcsProvider = "azureRepos"

	// CI providers params
	githubActions  ciProvider = "github-actions"
	jenkins        ciProvider = "jenkins"
	gitlab         ciProvider = "gitlab"
	azurePipelines ciProvider = "azure-pipelines"

	// JFrog platform environment variables
	JFrogUserEnv             = "JF_USER"
	JFrogUrlEnv              = "JF_URL"
	jfrogXrayUrlEnv          = "JF_XRAY_URL"
	jfrogArtifactoryUrlEnv   = "JF_ARTIFACTORY_URL"
	jfrogReleasesRepoEnv     = "JF_RELEASES_REPO"
	JFrogPasswordEnv         = "JF_PASSWORD"
	JFrogTokenEnv            = "JF_ACCESS_TOKEN"
	JfrogUseConfigProfileEnv = "JF_USE_CONFIG_PROFILE"
	JfrogConfigProfileEnv    = "JF_CONFIG_PROFILE"

	// Git environment variables
	GitProvider                      = "JF_GIT_PROVIDER"
	GitRepoOwnerEnv                  = "JF_GIT_OWNER"
	GitRepoEnv                       = "JF_GIT_REPO"
	GitProjectEnv                    = "JF_GIT_PROJECT"
	GitUsernameEnv                   = "JF_GIT_USERNAME"
	GitUseLocalRepositoryEnv         = "JF_USE_LOCAL_REPOSITORY"
	UseMostCommonAncestorAsTargetEnv = "JF_USE_MOST_COMMON_ANCESTOR_AS_TARGET"

	// Git naming template environment variables
	BranchNameTemplateEnv       = "JF_BRANCH_NAME_TEMPLATE"
	CommitMessageTemplateEnv    = "JF_COMMIT_MESSAGE_TEMPLATE"
	PullRequestTitleTemplateEnv = "JF_PULL_REQUEST_TITLE_TEMPLATE"
	PullRequestCommentTitleEnv  = "JF_PR_COMMENT_TITLE"
	//#nosec G101 -- not a secret
	PullRequestSecretCommentsEnv = "JF_PR_SHOW_SECRETS_COMMENTS"

	// Repository environment variables - Ignored if the frogbot-config.yml file is used
	InstallCommandEnv   = "JF_INSTALL_DEPS_CMD"
	MaxPnpmTreeDepthEnv = "JF_PNPM_MAX_TREE_DEPTH"
	RequirementsFileEnv = "JF_REQUIREMENTS_FILE"
	WorkingDirectoryEnv = "JF_WORKING_DIR"
	PathExclusionsEnv   = "JF_PATH_EXCLUSIONS"
	jfrogWatchesEnv     = "JF_WATCHES"
	jfrogProjectEnv     = "JF_PROJECT"
	// To include vulnerabilities and violations
	IncludeVulnerabilitiesEnv = "JF_INCLUDE_VULNERABILITIES"
	// To include all the vulnerabilities in the source branch at PR scan
	IncludeAllVulnerabilitiesEnv       = "JF_INCLUDE_ALL_VULNERABILITIES"
	AvoidPreviousPrCommentsDeletionEnv = "JF_AVOID_PREVIOUS_PR_COMMENTS_DELETION"
	AddPrCommentOnSuccessEnv           = "JF_PR_ADD_SUCCESS_COMMENT"
	FailOnSecurityIssuesEnv            = "JF_FAIL"
	UseWrapperEnv                      = "JF_USE_WRAPPER"
	DepsRepoEnv                        = "JF_DEPS_REPO"
	MinSeverityEnv                     = "JF_MIN_SEVERITY"
	FixableOnlyEnv                     = "JF_FIXABLE_ONLY"
	DisableJasEnv                      = "JF_DISABLE_ADVANCED_SECURITY"
	DetectionOnlyEnv                   = "JF_SKIP_AUTOFIX"
	AllowedLicensesEnv                 = "JF_ALLOWED_LICENSES"
	SkipAutoInstallEnv                 = "JF_SKIP_AUTO_INSTALL"
	AllowPartialResultsEnv             = "JF_ALLOW_PARTIAL_RESULTS"
	CommaDelimiter                     = ","

	// Email related environment variables
	//#nosec G101 -- False positive - no hardcoded credentials.
	SmtpPasswordEnv   = "JF_SMTP_PASSWORD"
	SmtpUserEnv       = "JF_SMTP_USER"
	SmtpServerEnv     = "JF_SMTP_SERVER"
	EmailReceiversEnv = "JF_EMAIL_RECEIVERS"

	//#nosec G101 -- False positive - no hardcoded credentials.
	GitTokenEnv          = "JF_GIT_TOKEN"
	GitBaseBranchEnv     = "JF_GIT_BASE_BRANCH"
	GitPullRequestIDEnv  = "JF_GIT_PULL_REQUEST_ID"
	GitApiEndpointEnv    = "JF_GIT_API_ENDPOINT"
	GitAggregateFixesEnv = "JF_GIT_AGGREGATE_FIXES"
	GitEmailAuthorEnv    = "JF_GIT_EMAIL_AUTHOR"

	// Product ID for usage reporting
	productId = "frogbot"

	// The 'GITHUB_ACTIONS' environment variable exists when the CI is GitHub Actions
	GitHubActionsEnv = "GITHUB_ACTIONS"

	// Placeholders for templates
	PackagePlaceHolder    = "{IMPACTED_PACKAGE}"
	FixVersionPlaceHolder = "{FIX_VERSION}"
	BranchHashPlaceHolder = "{BRANCH_NAME_HASH}"

	// General flags
	AvoidExtraMessages = "JF_AVOID_EXTRA_MESSAGES"

	// Default naming templates
	BranchNameTemplate                       = "frogbot-" + PackagePlaceHolder + "-" + BranchHashPlaceHolder
	AggregatedBranchNameTemplate             = "frogbot-update-" + BranchHashPlaceHolder + "-dependencies"
	CommitMessageTemplate                    = "Upgrade " + PackagePlaceHolder + " to " + FixVersionPlaceHolder
	PullRequestTitleTemplate                 = outputwriter.FrogbotTitlePrefix + " Update version of " + PackagePlaceHolder + " to " + FixVersionPlaceHolder
	AggregatePullRequestTitleDefaultTemplate = outputwriter.FrogbotTitlePrefix + " Update %s dependencies"
	// Frogbot Git author details showed in commits
	frogbotAuthorName  = "JFrog-Frogbot"
	frogbotAuthorEmail = "eco-system+frogbot@jfrog.com"
)

type UnsupportedErrorType string

const (
	IndirectDependencyFixNotSupported   UnsupportedErrorType = "IndirectDependencyFixNotSupported"
	BuildToolsDependencyFixNotSupported UnsupportedErrorType = "BuildToolsDependencyFixNotSupported"
	UnsupportedForFixVulnerableVersion  UnsupportedErrorType = "UnsupportedForFixVulnerableVersion"
)
