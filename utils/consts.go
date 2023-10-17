package utils

import (
	"github.com/jfrog/frogbot/utils/outputwriter"
)

type vcsProvider string

const (
	// Errors
	errUnsupportedMultiRepo = "multi repository configuration isn't supported. Only one repository configuration is allowed"

	// VCS providers params
	GitHub          vcsProvider = "github"
	GitLab          vcsProvider = "gitlab"
	BitbucketServer vcsProvider = "bitbucketServer"
	AzureRepos      vcsProvider = "azureRepos"

	// JFrog platform environment variables
	JFrogUserEnv           = "JF_USER"
	JFrogUrlEnv            = "JF_URL"
	jfrogXrayUrlEnv        = "JF_XRAY_URL"
	jfrogArtifactoryUrlEnv = "JF_ARTIFACTORY_URL"
	jfrogReleasesRepoEnv   = "JF_RELEASES_REPO"
	JFrogPasswordEnv       = "JF_PASSWORD"
	JFrogTokenEnv          = "JF_ACCESS_TOKEN"

	// Git environment variables
	GitProvider     = "JF_GIT_PROVIDER"
	GitRepoOwnerEnv = "JF_GIT_OWNER"
	GitRepoEnv      = "JF_GIT_REPO"
	GitProjectEnv   = "JF_GIT_PROJECT"
	GitUsernameEnv  = "JF_GIT_USERNAME"

	// Git naming template environment variables
	BranchNameTemplateEnv       = "JF_BRANCH_NAME_TEMPLATE"
	CommitMessageTemplateEnv    = "JF_COMMIT_MESSAGE_TEMPLATE"
	PullRequestTitleTemplateEnv = "JF_PULL_REQUEST_TITLE_TEMPLATE"

	// Repository environment variables - Ignored if the frogbot-config.yml file is used
	InstallCommandEnv                  = "JF_INSTALL_DEPS_CMD"
	RequirementsFileEnv                = "JF_REQUIREMENTS_FILE"
	WorkingDirectoryEnv                = "JF_WORKING_DIR"
	jfrogWatchesEnv                    = "JF_WATCHES"
	jfrogProjectEnv                    = "JF_PROJECT"
	IncludeAllVulnerabilitiesEnv       = "JF_INCLUDE_ALL_VULNERABILITIES"
	AvoidPreviousPrCommentsDeletionEnv = "JF_AVOID_PREVIOUS_PR_COMMENTS_DELETION"
	FailOnSecurityIssuesEnv            = "JF_FAIL"
	UseWrapperEnv                      = "JF_USE_WRAPPER"
	DepsRepoEnv                        = "JF_DEPS_REPO"
	MinSeverityEnv                     = "JF_MIN_SEVERITY"
	FixableOnlyEnv                     = "JF_FIXABLE_ONLY"
	AllowedLicensesEnv                 = "JF_ALLOWED_LICENSES"
	WatchesDelimiter                   = ","

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
