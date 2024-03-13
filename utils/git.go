package utils

import (
	"errors"
	"fmt"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp/capability"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/client"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/format/gitignore"
	"github.com/go-git/go-git/v5/plumbing/object"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

const (
	refFormat = "refs/heads/%s:refs/heads/%[1]s"

	// Timout is seconds for the git operations performed by the go-git client.
	goGitTimeoutSeconds = 120

	// Separators used to convert technologies array into string
	fixBranchTechSeparator        = "-"
	pullRequestTitleTechSeparator = ","
)

type GitManager struct {
	// repository represents a git repository as a .git dir.
	localGitRepository *git.Repository
	// remoteName is name of the Git remote server
	remoteName string
	// remoteGitUrl is a URL in HTTPS protocol, to clone the repository
	remoteGitUrl string
	// The authentication struct consisting a username/password
	auth *githttp.BasicAuth
	// dryRun is used for testing purposes, mocking part of the git commands that requires networking
	dryRun bool
	// When dryRun is enabled, dryRunRepoPath specifies the repository local path to clone
	dryRunRepoPath string
	// When dryRun is enabled, skipClone allows skipping the cloning of a repository for testing purposes
	SkipClone bool
	// Custom naming formats
	customTemplates CustomTemplates
	// Git details
	git *Git
}

type CustomTemplates struct {
	// New commit message template
	commitMessageTemplate string
	// New branch name template
	branchNameTemplate string
	// New pull request title template
	pullRequestTitleTemplate string
}

func NewGitManager() *GitManager {
	setGoGitCustomClient()
	return &GitManager{}
}

func (gm *GitManager) SetAuth(username, token string) *GitManager {
	gm.auth = toBasicAuth(username, token)
	return gm
}

func (gm *GitManager) SetRemoteGitUrl(remoteHttpsGitUrl string) (*GitManager, error) {
	// Check if the .git directory exists
	dotGitExists, err := fileutils.IsDirExists(git.GitDirName, false)
	if err != nil {
		return nil, err
	}
	if !dotGitExists {
		// If .git directory doesn't exist, create it with the given remote URL
		gm.remoteGitUrl = remoteHttpsGitUrl
		if err = vcsutils.CreateDotGitFolderWithRemote(".", vcsutils.RemoteName, remoteHttpsGitUrl); err != nil {
			return gm, err
		}
	}

	if gm.localGitRepository == nil {
		if _, err = gm.SetLocalRepository(); err != nil {
			return gm, err
		}
	}

	gitRemote, err := gm.localGitRepository.Remote(gm.remoteName)
	if err != nil {
		return nil, fmt.Errorf("'git remote %s' failed with error: %s", gm.remoteName, err.Error())
	}

	if len(gitRemote.Config().URLs) < 1 {
		return nil, errors.New("failed to find git remote URL")
	}

	gm.remoteGitUrl = gitRemote.Config().URLs[0]

	// If the remote URL in the .git directory is not using the HTTPS protocol, update remoteGitUrl to use HTTPS protocol.
	if !strings.HasPrefix(gm.remoteGitUrl, "https://") {
		gm.remoteGitUrl = remoteHttpsGitUrl
	}
	return gm, nil
}

func (gm *GitManager) SetLocalRepository() (*GitManager, error) {
	var err error
	// Re-initialize the repository and update remoteName
	gm.remoteName = vcsutils.RemoteName
	gm.localGitRepository, err = git.PlainOpen(".")
	return gm, err
}

func (gm *GitManager) SetGitParams(gitParams *Git) (*GitManager, error) {
	var err error
	if gm.customTemplates, err = loadCustomTemplates(gitParams.CommitMessageTemplate, gitParams.BranchNameTemplate, gitParams.PullRequestTitleTemplate); err != nil {
		return nil, err
	}
	gm.git = gitParams
	return gm, nil
}

func (gm *GitManager) SetEmailAuthor(emailAuthor string) *GitManager {
	if gm.git == nil {
		gm.git = &Git{}
	}
	gm.git.EmailAuthor = emailAuthor
	return gm
}

func (gm *GitManager) SetDryRun(dryRun bool, dryRunRepoPath string) *GitManager {
	gm.dryRun = dryRun
	gm.dryRunRepoPath = dryRunRepoPath
	return gm
}

func (gm *GitManager) Checkout(branchName string) error {
	log.Debug("Running git checkout to branch:", branchName)
	if err := gm.createBranchAndCheckout(branchName, false, false); err != nil {
		return fmt.Errorf("'git checkout %s' failed with error: %s", branchName, err.Error())
	}
	return nil
}

func (gm *GitManager) Clone(destinationPath, branchName string) error {
	if gm.dryRun {
		// "Clone" the repository from the testdata folder
		return gm.dryRunClone(destinationPath)
	}

	transport.UnsupportedCapabilities = []capability.Capability{
		capability.ThinPack,
	}
	log.Debug(fmt.Sprintf("Running git clone %s (%s branch)...", gm.remoteGitUrl, branchName))
	cloneOptions := &git.CloneOptions{
		URL:           gm.remoteGitUrl,
		Auth:          gm.auth,
		RemoteName:    gm.remoteName,
		ReferenceName: GetFullBranchName(branchName),
		SingleBranch:  true,
		Depth:         1,
		Tags:          git.NoTags,
	}
	repo, err := git.PlainClone(destinationPath, false, cloneOptions)
	if err != nil {
		return fmt.Errorf("git clone %s from %s failed with error: %s", branchName, gm.remoteGitUrl, err.Error())
	}
	gm.localGitRepository = repo
	log.Debug(fmt.Sprintf("Project cloned from %s to %s", gm.remoteGitUrl, destinationPath))
	return nil
}

// Creates a new branch and switches to it.
// If keepLocalChanges is set to true, all changes made on the current branch before switching to the new one will be transferred to the new branch.
func (gm *GitManager) CreateBranchAndCheckout(branchName string, keepLocalChanges bool) error {
	log.Debug("Creating branch", branchName, "...")
	err := gm.createBranchAndCheckout(branchName, true, keepLocalChanges)
	if err != nil {
		// Don't fail on dryRuns as we operate on local repositories, branch could be existing.
		if gm.dryRun {
			return nil
		}
		if errors.Is(err, plumbing.ErrReferenceNotFound) {
			return err
		}
		err = fmt.Errorf("failed upon creating/checkout branch '%s' with error: %s", branchName, err.Error())
	}
	return err
}

func (gm *GitManager) createBranchAndCheckout(branchName string, create bool, keepLocalChanges bool) error {
	var checkoutConfig *git.CheckoutOptions
	if keepLocalChanges {
		checkoutConfig = &git.CheckoutOptions{
			Create: create,
			Branch: GetFullBranchName(branchName),
			Keep:   true,
		}
	} else {
		checkoutConfig = &git.CheckoutOptions{
			Create: create,
			Branch: GetFullBranchName(branchName),
			Force:  true,
		}
	}
	worktree, err := gm.localGitRepository.Worktree()
	if err != nil {
		return err
	}
	return worktree.Checkout(checkoutConfig)
}

func getCurrentBranch(repository *git.Repository) (string, error) {
	head, err := repository.Head()
	if err != nil {
		return "", err
	}
	return head.Name().Short(), nil
}

func (gm *GitManager) AddAllAndCommit(commitMessage string) error {
	log.Debug("Running git add all and commit...")
	err := gm.addAll()
	if err != nil {
		return err
	}
	return gm.commit(commitMessage)
}

func (gm *GitManager) addAll() error {
	worktree, err := gm.localGitRepository.Worktree()
	if err != nil {
		return err
	}

	// AddWithOptions doesn't exclude files in .gitignore, so we add their contents as exclusions explicitly.
	ignorePatterns, err := gitignore.ReadPatterns(worktree.Filesystem, nil)
	if err != nil {
		return err
	}
	worktree.Excludes = append(worktree.Excludes, ignorePatterns...)
	status, err := worktree.Status()
	if err != nil {
		return err
	}

	err = worktree.AddWithOptions(&git.AddOptions{All: true})
	if err != nil {
		return fmt.Errorf("git add failed with error: %s", err.Error())
	}
	// go-git add all using AddWithOptions doesn't include deleted files, that's why we need to double-check
	for fileName, fileStatus := range status {
		if fileStatus.Worktree == git.Deleted {
			_, err = worktree.Add(fileName)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (gm *GitManager) commit(commitMessage string) error {
	worktree, err := gm.localGitRepository.Worktree()
	if err != nil {
		return err
	}
	_, err = worktree.Commit(commitMessage, &git.CommitOptions{
		Author: &object.Signature{
			Name:  frogbotAuthorName,
			Email: gm.git.EmailAuthor,
			When:  time.Now(),
		},
	})
	if err != nil {
		err = fmt.Errorf("git commit failed with error: %s", err.Error())
	}
	return err
}

func (gm *GitManager) BranchExistsInRemote(branchName string) (bool, error) {
	if gm.dryRun {
		return false, nil
	}
	remote, err := gm.localGitRepository.Remote(gm.remoteName)
	if err != nil {
		return false, errorutils.CheckError(err)
	}
	refList, err := remote.List(&git.ListOptions{Auth: gm.auth})
	if err != nil {
		return false, errorutils.CheckError(err)
	}
	refName := plumbing.NewBranchReferenceName(branchName)
	for _, ref := range refList {
		if refName.String() == ref.Name().String() {
			return true, nil
		}
	}
	return false, nil
}

func (gm *GitManager) RemoveRemoteBranch(branchName string) error {
	remote, err := gm.localGitRepository.Remote(gm.remoteName)
	if err != nil {
		return err
	}
	return remote.Push(&git.PushOptions{
		Auth:     gm.auth,
		RefSpecs: []config.RefSpec{config.RefSpec(":refs/heads/" + branchName)},
	})
}

func (gm *GitManager) Push(force bool, branchName string) error {
	log.Debug("Pushing branch:", branchName, "...")
	if gm.dryRun {
		// On dry run do not push to any remote
		return nil
	}
	// Pushing to remote
	if err := gm.localGitRepository.Push(&git.PushOptions{
		RemoteName: gm.remoteName,
		Auth:       gm.auth,
		Force:      force,
		RefSpecs:   []config.RefSpec{config.RefSpec(fmt.Sprintf(refFormat, branchName))},
	}); err != nil {
		return fmt.Errorf("git push failed with error: %s", err.Error())
	}
	return nil
}

// IsClean returns true if all the files are in Unmodified status.
func (gm *GitManager) IsClean() (bool, error) {
	worktree, err := gm.localGitRepository.Worktree()
	if err != nil {
		return false, err
	}
	status, err := worktree.Status()
	if err != nil {
		return false, err
	}

	return status.IsClean(), nil
}

func (gm *GitManager) GenerateCommitMessage(impactedPackage string, fixVersion string) string {
	template := gm.customTemplates.commitMessageTemplate
	if template == "" {
		template = CommitMessageTemplate
	}
	return formatStringWithPlaceHolders(template, impactedPackage, fixVersion, "", "", true)
}

func (gm *GitManager) GenerateAggregatedCommitMessage(tech []coreutils.Technology) string {
	template := gm.customTemplates.commitMessageTemplate
	if template == "" {
		// In aggregated mode, commit message and PR title are the same.
		template = gm.GenerateAggregatedPullRequestTitle(tech)
	}
	return formatStringWithPlaceHolders(template, "", "", "", "", true)
}

func formatStringWithPlaceHolders(str, impactedPackage, fixVersion, hash, baseBranch string, allowSpaces bool) string {
	replacements := []struct {
		placeholder string
		value       string
	}{
		{PackagePlaceHolder, impactedPackage},
		{FixVersionPlaceHolder, fixVersion},
		{BranchHashPlaceHolder, hash},
	}
	for _, r := range replacements {
		// Replace placeholders with their corresponding values
		// Try also with dollar sign ($) prefix, to ensure backward compatibility.
		str = strings.Replace(str, "$"+r.placeholder, r.value, 1)
		str = strings.Replace(str, r.placeholder, r.value, 1)
	}
	if !allowSpaces {
		str = strings.ReplaceAll(str, " ", "_")
	}
	// Add baseBranch suffix if needed.
	if baseBranch != "" {
		str += "-" + baseBranch
	}

	return str
}

func (gm *GitManager) GenerateFixBranchName(branch string, impactedPackage string, fixVersion string, projectName string) (string, error) {
	hash, err := Md5Hash("frogbot", branch, impactedPackage, fixVersion, projectName)
	if err != nil {
		return "", err
	}
	// Package names in Maven usually contain colons, which are not allowed in a branch name
	fixedPackageName := strings.ReplaceAll(impactedPackage, ":", "_")
	branchFormat := gm.customTemplates.branchNameTemplate
	if branchFormat == "" {
		branchFormat = BranchNameTemplate
	}
	return formatStringWithPlaceHolders(branchFormat, fixedPackageName, fixVersion, hash, "", false), nil
}

func (gm *GitManager) GeneratePullRequestTitle(impactedPackage string, version string, projectName string) string {
	template := PullRequestTitleTemplate
	if projectName != "" {
		template += " (" + projectName + ")"
	}
	pullRequestFormat := gm.customTemplates.pullRequestTitleTemplate
	if pullRequestFormat != "" {
		template = pullRequestFormat
	}
	return formatStringWithPlaceHolders(template, impactedPackage, version, "", "", true)
}

func (gm *GitManager) GenerateAggregatedPullRequestTitle(tech []coreutils.Technology) string {
	template := gm.getPullRequestTitleTemplate(tech)
	// If no technologies are provided, return the template as-is
	if len(tech) == 0 {
		return normalizeWhitespaces(strings.ReplaceAll(template, "%s", ""))
	}
	return fmt.Sprintf(template, techArrayToString(tech, pullRequestTitleTechSeparator))
}

func (gm *GitManager) getPullRequestTitleTemplate(tech []coreutils.Technology) string {
	// Check if a custom template is available
	if customTemplate := gm.customTemplates.pullRequestTitleTemplate; customTemplate != "" {
		return parseCustomTemplate(customTemplate, tech)
	}
	// If no custom template, use the default template
	return AggregatePullRequestTitleDefaultTemplate
}

// GenerateAggregatedFixBranchName Generating a consistent branch name to enable branch updates
// and to ensure that there is only one Frogbot aggregate pull request from each base branch scanned.
func (gm *GitManager) GenerateAggregatedFixBranchName(baseBranch string, tech []coreutils.Technology) (fixBranchName string) {
	branchFormat := gm.customTemplates.branchNameTemplate
	if branchFormat == "" {
		branchFormat = AggregatedBranchNameTemplate
	}
	return formatStringWithPlaceHolders(branchFormat, "", "", techArrayToString(tech, fixBranchTechSeparator), baseBranch, false)
}

// dryRunClone clones an existing repository from our testdata folder into the destination folder for testing purposes.
// We should call this function when the current working directory is the repository we want to clone.
func (gm *GitManager) dryRunClone(destination string) error {
	// Set the git repository to the new destination .git folder
	repo, err := git.PlainOpen(destination)
	if err != nil {
		return err
	}
	gm.localGitRepository = repo
	return nil
}

func toBasicAuth(username, token string) *githttp.BasicAuth {
	// The username can be anything except for an empty string
	if username == "" {
		username = "username"
	}
	// Bitbucket server username starts with ~ prefix as the project key. We need to trim it for the authentication
	username = strings.TrimPrefix(username, "~")
	return &githttp.BasicAuth{
		Username: username,
		Password: token,
	}
}

// GetFullBranchName returns the full branch name (for example: refs/heads/master)
// The input branchName can be a short name (master) or a full name (refs/heads/master)
func GetFullBranchName(branchName string) plumbing.ReferenceName {
	return plumbing.NewBranchReferenceName(plumbing.ReferenceName(branchName).Short())
}

func loadCustomTemplates(commitMessageTemplate, branchNameTemplate, pullRequestTitleTemplate string) (customTemplates CustomTemplates, err error) {
	customTemplates = CustomTemplates{
		commitMessageTemplate:    commitMessageTemplate,
		branchNameTemplate:       branchNameTemplate,
		pullRequestTitleTemplate: pullRequestTitleTemplate,
	}
	// Validate correct branch by Git providers restrictions.
	err = validateBranchName(customTemplates.branchNameTemplate)
	return
}

func setGoGitCustomClient() {
	log.Debug("Setting timeout for go-git to", goGitTimeoutSeconds, "seconds ...")
	customClient := &http.Client{
		Timeout: goGitTimeoutSeconds * time.Second,
	}
	client.InstallProtocol("http", githttp.NewClient(customClient))
	client.InstallProtocol("https", githttp.NewClient(customClient))
}

// Clean user template from input strings and add suffix.
func parseCustomTemplate(customTemplate string, tech []coreutils.Technology) string {
	trimSpace := strings.TrimSpace(customTemplate)
	// Find any input format strings
	re := regexp.MustCompile(`%[sdvTtqwxXbcdoUxfeEgGp]`)
	// Replace all matching substrings with an empty string
	result := re.ReplaceAllString(trimSpace, "")
	// Remove any middle spaces
	result = strings.Join(strings.Fields(result), " ")
	var suffix string
	if len(tech) > 0 {
		suffix = " - %s Dependencies"
	}
	return normalizeWhitespaces(result) + suffix
}
