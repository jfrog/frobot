package utils

import (
	"errors"
	"fmt"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/tests"
	"github.com/stretchr/testify/assert"
	"os"
	"path/filepath"
	"testing"
)

func TestGitManager_GenerateCommitMessage(t *testing.T) {
	testCases := []struct {
		gitManager      GitManager
		impactedPackage string
		fixVersion      VulnerabilityDetails
		expected        string
		description     string
	}{
		{
			gitManager:      GitManager{customTemplates: CustomTemplates{commitMessageTemplate: "<type>: bump ${IMPACTED_PACKAGE}"}},
			impactedPackage: "mquery",
			fixVersion:      VulnerabilityDetails{SuggestedFixedVersion: "3.4.5"},
			expected:        "<type>: bump mquery",
			description:     "Custom prefix",
		},
		{
			gitManager:      GitManager{customTemplates: CustomTemplates{commitMessageTemplate: "<type>[scope]: Upgrade package ${IMPACTED_PACKAGE} to ${FIX_VERSION}"}},
			impactedPackage: "mquery", fixVersion: VulnerabilityDetails{SuggestedFixedVersion: "3.4.5"},
			expected:    "<type>[scope]: Upgrade package mquery to 3.4.5",
			description: "Default template",
		}, {
			gitManager:      GitManager{customTemplates: CustomTemplates{commitMessageTemplate: ""}},
			impactedPackage: "mquery", fixVersion: VulnerabilityDetails{SuggestedFixedVersion: "3.4.5"},
			expected:    "Upgrade mquery to 3.4.5",
			description: "Default template",
		},
		// Test template without $
		{
			gitManager:      GitManager{customTemplates: CustomTemplates{commitMessageTemplate: "<type>[scope]: Upgrade package {IMPACTED_PACKAGE} to {FIX_VERSION}"}},
			impactedPackage: "mquery", fixVersion: VulnerabilityDetails{SuggestedFixedVersion: "3.4.5"},
			expected:    "<type>[scope]: Upgrade package mquery to 3.4.5",
			description: "Default template",
		},
		{
			gitManager:      GitManager{customTemplates: CustomTemplates{commitMessageTemplate: "<type>[scope]: Upgrade package ${IMPACTED_PACKAGE} to {FIX_VERSION}"}},
			impactedPackage: "mquery", fixVersion: VulnerabilityDetails{SuggestedFixedVersion: "3.4.5"},
			expected:    "<type>[scope]: Upgrade package mquery to 3.4.5",
			description: "Default template",
		},
	}
	for _, test := range testCases {
		t.Run(test.expected, func(t *testing.T) {
			commitMessage := test.gitManager.GenerateCommitMessage(test.impactedPackage, test.fixVersion.SuggestedFixedVersion)
			assert.Equal(t, test.expected, commitMessage)
		})
	}
}

func TestGitManager_GenerateFixBranchName(t *testing.T) {
	testCases := []struct {
		gitManager      GitManager
		impactedPackage string
		fixVersion      VulnerabilityDetails
		expected        string
		description     string
		projectName     string
	}{
		{
			gitManager:      GitManager{customTemplates: CustomTemplates{branchNameTemplate: "[Feature]-${IMPACTED_PACKAGE}-${BRANCH_NAME_HASH}"}},
			impactedPackage: "mquery",
			fixVersion:      VulnerabilityDetails{SuggestedFixedVersion: "3.4.5"},
			expected:        "[Feature]-mquery-41b1f45136b25e3624b15999bd57a476",
			description:     "Custom template",
		},
		{
			gitManager:      GitManager{customTemplates: CustomTemplates{branchNameTemplate: ""}},
			impactedPackage: "mquery",
			fixVersion:      VulnerabilityDetails{SuggestedFixedVersion: "3.4.5"},
			expected:        "frogbot-mquery-41b1f45136b25e3624b15999bd57a476",
			description:     "No template",
		},
		{
			gitManager:      GitManager{customTemplates: CustomTemplates{branchNameTemplate: "just-a-branch-${BRANCH_NAME_HASH}"}},
			impactedPackage: "mquery",
			fixVersion:      VulnerabilityDetails{SuggestedFixedVersion: "3.4.5"},
			expected:        "just-a-branch-41b1f45136b25e3624b15999bd57a476",
			description:     "Custom template without inputs",
		},
		{
			gitManager:      GitManager{customTemplates: CustomTemplates{branchNameTemplate: "just-a-branch-${BRANCH_NAME_HASH}"}},
			impactedPackage: "mquery",
			fixVersion:      VulnerabilityDetails{SuggestedFixedVersion: "3.4.5"},
			expected:        "just-a-branch-576bdc1ddb2ad676551efd7a47f48ece",
			description:     "Custom template without inputs",
			projectName:     "my-identifier",
		},
	}
	for _, test := range testCases {
		t.Run(test.expected, func(t *testing.T) {
			commitMessage, err := test.gitManager.GenerateFixBranchName("md5Branch", test.impactedPackage, test.fixVersion.SuggestedFixedVersion, test.projectName)
			assert.NoError(t, err)
			assert.Equal(t, test.expected, commitMessage)
		})
	}
}

func TestGitManager_GeneratePullRequestTitle(t *testing.T) {
	testCases := []struct {
		gitManager      GitManager
		impactedPackage string
		fixVersion      VulnerabilityDetails
		expected        string
		description     string
		projectName     string
	}{
		{
			gitManager:      GitManager{customTemplates: CustomTemplates{pullRequestTitleTemplate: "[CustomPR] update ${IMPACTED_PACKAGE} to ${FIX_VERSION}"}},
			impactedPackage: "mquery",
			fixVersion:      VulnerabilityDetails{SuggestedFixedVersion: "3.4.5"},
			expected:        "[CustomPR] update mquery to 3.4.5",
			description:     "Custom template",
		},
		{
			gitManager:      GitManager{customTemplates: CustomTemplates{pullRequestTitleTemplate: "[CustomPR] update ${IMPACTED_PACKAGE}"}},
			impactedPackage: "mquery",
			fixVersion:      VulnerabilityDetails{SuggestedFixedVersion: "3.4.5"},
			expected:        "[CustomPR] update mquery",
			description:     "Custom template one var",
		},
		{
			gitManager:      GitManager{customTemplates: CustomTemplates{pullRequestTitleTemplate: ""}},
			impactedPackage: "mquery",
			fixVersion:      VulnerabilityDetails{SuggestedFixedVersion: "3.4.5"},
			expected:        "[🐸 Frogbot] Update version of mquery to 3.4.5",
			description:     "No prefix",
		},
		{
			gitManager:      GitManager{customTemplates: CustomTemplates{pullRequestTitleTemplate: ""}},
			impactedPackage: "mquery",
			fixVersion:      VulnerabilityDetails{SuggestedFixedVersion: "3.4.5"},
			expected:        "[🐸 Frogbot] Update version of mquery to 3.4.5 (my-identifier)",
			description:     "No prefix",
			projectName:     "my-identifier",
		},
	}
	for _, test := range testCases {
		t.Run(test.expected, func(t *testing.T) {
			titleOutput := test.gitManager.GeneratePullRequestTitle(test.impactedPackage, test.fixVersion.SuggestedFixedVersion, test.projectName)
			assert.Equal(t, test.expected, titleOutput)
		})
	}
}

func TestGitManager_GenerateAggregatedFixBranchName(t *testing.T) {
	testCases := []struct {
		gitManager GitManager
		baseBranch string
		expected   string
		desc       string
	}{
		{
			expected:   "frogbot-update-Go-dependencies-main",
			baseBranch: "main",
			desc:       "No template",
			gitManager: GitManager{},
		}, {
			expected:   "frogbot-update-Go-dependencies-v2",
			baseBranch: "v2",
			desc:       "No template",
			gitManager: GitManager{},
		},
		{
			expected:   "[feature]-Go-main",
			baseBranch: "main",
			desc:       "Custom template hash only",
			gitManager: GitManager{customTemplates: CustomTemplates{branchNameTemplate: "[feature]-${BRANCH_NAME_HASH}"}},
		}, {
			expected:   "[feature]-Go-master",
			baseBranch: "master",
			desc:       "Custom template hash only",
			gitManager: GitManager{customTemplates: CustomTemplates{branchNameTemplate: "[feature]-${BRANCH_NAME_HASH}"}},
		},
	}
	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			titleOutput := test.gitManager.GenerateAggregatedFixBranchName(test.baseBranch, []coreutils.Technology{coreutils.Go})
			assert.Equal(t, test.expected, titleOutput)
		})
	}
}

func TestGitManager_GenerateAggregatedCommitMessage(t *testing.T) {
	testCases := []struct {
		gitManager GitManager
		expected   string
	}{
		{gitManager: GitManager{}, expected: "[🐸 Frogbot] Update Pipenv dependencies"},
		{gitManager: GitManager{customTemplates: CustomTemplates{commitMessageTemplate: "custom_template"}}, expected: "custom_template"},
	}
	for _, test := range testCases {
		t.Run(test.expected, func(t *testing.T) {
			commit := test.gitManager.GenerateAggregatedCommitMessage([]coreutils.Technology{coreutils.Pipenv})
			assert.Equal(t, commit, test.expected)
		})
	}
}

func TestGitManager_Checkout(t *testing.T) {
	testCases := []struct {
		withLocalChanges bool
	}{
		{
			withLocalChanges: false,
		},
		{
			withLocalChanges: true,
		},
	}

	for _, test := range testCases {
		t.Run(fmt.Sprintf("test branch checkout: local changes:%t", test.withLocalChanges), func(t *testing.T) {
			tmpDir, err := fileutils.CreateTempDir()
			assert.NoError(t, err)
			defer func() {
				assert.NoError(t, fileutils.RemoveTempDir(tmpDir))
			}()
			var restoreWd func() error
			restoreWd, err = Chdir(tmpDir)
			assert.NoError(t, err)
			defer func() {
				assert.NoError(t, restoreWd())
			}()
			gitManager := createFakeDotGit(t, tmpDir)
			// Get the current branch that is set as HEAD
			headRef, err := gitManager.localGitRepository.Head()
			assert.NoError(t, err)
			assert.Equal(t, headRef.Name().Short(), "master")

			if test.withLocalChanges {
				// Create new file in master branch
				tempFilePath := filepath.Join(tmpDir, "myFile.txt")
				var file *os.File
				file, err = os.Create(tempFilePath)
				assert.NoError(t, err)
				assert.NoError(t, file.Close())

				// Create 'dev' branch and checkout
				err = gitManager.CreateBranchAndCheckout("dev", true)
				assert.NoError(t, err)

				// Verify that temp file exist in new branch
				var fileExists bool
				fileExists, err = fileutils.IsFileExists(tempFilePath, false)
				assert.NoError(t, err)
				assert.True(t, fileExists)
			} else {
				// Create 'dev' branch and checkout
				err = gitManager.CreateBranchAndCheckout("dev", false)
				assert.NoError(t, err)
			}

			var currBranch string
			currBranch, err = getCurrentBranch(gitManager.localGitRepository)
			assert.NoError(t, err)
			assert.Equal(t, "dev", currBranch)

			// Checkout back to 'master'
			assert.NoError(t, gitManager.Checkout("master"))
			currBranch, err = getCurrentBranch(gitManager.localGitRepository)
			assert.NoError(t, err)
			assert.Equal(t, "master", currBranch)
		})
	}
}

func createFakeDotGit(t *testing.T, testPath string) *GitManager {
	// Initialize a new in-memory repository
	repo, err := git.PlainInit(testPath, false)
	assert.NoError(t, err)
	// Create a new file and add it to the worktree
	filename := "README.md"
	content := []byte("# My New Repository\n\nThis is a sample repository created using go-git.")
	err = os.WriteFile(filename, content, 0644)
	assert.NoError(t, err)
	worktree, err := repo.Worktree()
	assert.NoError(t, err)
	_, err = worktree.Add(filename)
	assert.NoError(t, err)
	// Commit the changes to the new main branch
	_, err = worktree.Commit("Initial commit", &git.CommitOptions{
		Author: &object.Signature{
			Name:  "Your Name",
			Email: "your@email.com",
		},
	})
	assert.NoError(t, err)
	manager := NewGitManager().SetDryRun(true, testPath)
	manager.localGitRepository = repo
	manager.remoteName = vcsutils.RemoteName
	assert.NoError(t, err)
	return manager
}

func TestGitManager_SetRemoteGitUrl(t *testing.T) {
	testCases := []struct {
		description       string
		dotGitExists      bool
		remoteGitUrl      string
		remoteHttpsGitUrl string
		existingRemoteUrl string
		expectedError     error
		expectedGitUrl    string
	}{
		{
			description:       "DotGit does not exist",
			dotGitExists:      false,
			remoteHttpsGitUrl: "https://example.com/owner/repo.git",
			expectedGitUrl:    "https://example.com/owner/repo.git",
		},
		{
			description:       "DotGit exists, no remote found",
			dotGitExists:      true,
			remoteHttpsGitUrl: "https://example.com/owner/repo.git",
			expectedError:     errors.New("'git remote origin' failed with error: remote not found"),
		},
		{
			description:       "DotGit exists, remote URL exists with HTTPS protocol",
			dotGitExists:      true,
			remoteHttpsGitUrl: "https://example.com/owner/repo.git",
			existingRemoteUrl: "https://example.com/owner/repo.git",
			expectedGitUrl:    "https://example.com/owner/repo.git",
		},
		{
			description:       "DotGit exists, remote URL is not HTTPS",
			dotGitExists:      true,
			remoteHttpsGitUrl: "https://example.com/owner/repo.git",
			existingRemoteUrl: "ssh://example.com/owner/repo.git",
			// Should be updated to the new HTTPS URL
			expectedGitUrl: "https://example.com/owner/repo.git",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			tmpDir, err := fileutils.CreateTempDir()
			assert.NoError(t, err)
			baseDir, err := os.Getwd()
			assert.NoError(t, err)
			restoreFunc := tests.ChangeDirWithCallback(t, baseDir, tmpDir)
			defer restoreFunc()
			gm := NewGitManager().SetDryRun(true, tmpDir)
			if tc.dotGitExists {
				gm = createFakeDotGit(t, tmpDir)
			}
			if tc.existingRemoteUrl != "" {
				_, err = gm.localGitRepository.CreateRemote(&config.RemoteConfig{
					Name: vcsutils.RemoteName,
					URLs: []string{tc.existingRemoteUrl},
				})
				assert.NoError(t, err)
			}
			_, err = gm.SetRemoteGitUrl(tc.remoteHttpsGitUrl)
			if err != nil {
				assert.EqualError(t, tc.expectedError, err.Error())
			} else {
				assert.Nil(t, err)
			}
			assert.Equal(t, tc.expectedGitUrl, gm.remoteGitUrl)
		})
	}
}

func TestGetAggregatedPullRequestTitle(t *testing.T) {
	defaultGm := GitManager{}
	testsCases := []struct {
		tech     []coreutils.Technology
		gm       GitManager
		expected string
	}{
		{gm: defaultGm, tech: []coreutils.Technology{}, expected: "[🐸 Frogbot] Update dependencies"},
		{gm: defaultGm, tech: []coreutils.Technology{coreutils.Maven}, expected: "[🐸 Frogbot] Update Maven dependencies"},
		{gm: defaultGm, tech: []coreutils.Technology{coreutils.Gradle}, expected: "[🐸 Frogbot] Update Gradle dependencies"},
		{gm: defaultGm, tech: []coreutils.Technology{coreutils.Npm}, expected: "[🐸 Frogbot] Update npm dependencies"},
		{gm: defaultGm, tech: []coreutils.Technology{coreutils.Yarn}, expected: "[🐸 Frogbot] Update Yarn dependencies"},
		{gm: GitManager{customTemplates: CustomTemplates{pullRequestTitleTemplate: "[Dependencies] My template "}}, tech: []coreutils.Technology{coreutils.Yarn}, expected: "[Dependencies] My template - Yarn Dependencies"},
		{gm: GitManager{customTemplates: CustomTemplates{pullRequestTitleTemplate: ""}}, tech: []coreutils.Technology{coreutils.Yarn}, expected: "[🐸 Frogbot] Update Yarn dependencies"},
		{gm: GitManager{customTemplates: CustomTemplates{pullRequestTitleTemplate: "[Feature] %s hello"}}, tech: []coreutils.Technology{coreutils.Yarn}, expected: "[Feature] hello - Yarn Dependencies"},
		{gm: GitManager{customTemplates: CustomTemplates{pullRequestTitleTemplate: "[Feature] %s %d hello"}}, tech: []coreutils.Technology{coreutils.Yarn}, expected: "[Feature] hello - Yarn Dependencies"},
		{gm: GitManager{customTemplates: CustomTemplates{pullRequestTitleTemplate: "[Feature] %s %d hello"}}, tech: []coreutils.Technology{coreutils.Yarn}, expected: "[Feature] hello - Yarn Dependencies"},
		{gm: GitManager{customTemplates: CustomTemplates{pullRequestTitleTemplate: "[Feature] %s %f hello"}}, tech: []coreutils.Technology{coreutils.Yarn, coreutils.Go}, expected: "[Feature] hello - Yarn,Go Dependencies"},
		{gm: GitManager{customTemplates: CustomTemplates{pullRequestTitleTemplate: "[Feature] %s %d hello"}}, tech: []coreutils.Technology{coreutils.Yarn, coreutils.Go, coreutils.Npm}, expected: "[Feature] hello - Yarn,Go,npm Dependencies"},
		{gm: GitManager{customTemplates: CustomTemplates{pullRequestTitleTemplate: "[Feature] %s %d hello"}}, tech: []coreutils.Technology{}, expected: "[Feature] hello"},
	}
	for _, test := range testsCases {
		t.Run(test.expected, func(t *testing.T) {
			title := test.gm.GenerateAggregatedPullRequestTitle(test.tech)
			assert.Equal(t, test.expected, title)
		})
	}
}
