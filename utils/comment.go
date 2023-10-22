package utils

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/jfrog/frogbot/utils/outputwriter"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

type ReviewCommentType string

type ReviewComment struct {
	Location    formats.Location
	Type        ReviewCommentType
	CommentInfo vcsclient.PullRequestComment
}

const (
	ApplicableComment ReviewCommentType = "Applicable"
	IacComment        ReviewCommentType = "Iac"
	SastComment       ReviewCommentType = "Sast"

	RescanRequestComment   = "rescan"
	commentRemovalErrorMsg = "An error occurred while attempting to remove older Frogbot pull request comments:"
)

func HandlePullRequestCommentsAfterScan(issues *IssuesCollection, repo *Repository, client vcsclient.VcsClient, pullRequestID int) (err error) {
	if !repo.Params.AvoidPreviousPrCommentsDeletion {
		// The removal of comments may fail for various reasons,
		// such as concurrent scanning of pull requests and attempts
		// to delete comments that have already been removed in a different process.
		// Since this task is not mandatory for a Frogbot run,
		// we will not cause a Frogbot run to fail but will instead log the error.
		log.Debug("Looking for an existing Frogbot pull request comment. Deleting it if it exists...")
		// Delete previous PR regular comments, if exists (not related to location of a change)
		if err = DeleteExistingPullRequestComments(repo, client); err != nil {
			log.Error(fmt.Sprintf("%s:\n%v", commentRemovalErrorMsg, err))
			return
		}
		// Delete previous PR review comments, if exists (related to location of a change)
		if err = DeleteExistingPullRequestReviewComments(repo, pullRequestID, client); err != nil {
			log.Error(fmt.Sprintf("%s:\n%v", commentRemovalErrorMsg, err))
			return
		}
	}

	// Add summary (SCA, license) scan comment
	if err = client.AddPullRequestComment(context.Background(), repo.RepoOwner, repo.RepoName, generatePullRequestSummaryComment(issues, repo.OutputWriter), pullRequestID); err != nil {
		err = errors.New("couldn't add pull request comment: " + err.Error())
		return
	}

	// Handle review comments at the pull request
	if err = addReviewComments(repo, pullRequestID, client, issues); err != nil {
		err = errors.New("couldn't add pull request review comments: " + err.Error())
		return
	}
	return
}

// Delete existing pull request regular comments (Summary, Fallback review comments)
func DeleteExistingPullRequestComments(repository *Repository, client vcsclient.VcsClient) error {
	prDetails := repository.PullRequestDetails
	comments, err := GetSortedPullRequestComments(client, prDetails.Target.Owner, prDetails.Target.Repository, int(prDetails.ID))
	if err != nil {
		return fmt.Errorf(
			"failed to get comments. the following details were used in order to fetch the comments: <%s/%s> pull request #%d. the error received: %s",
			repository.RepoOwner, repository.RepoName, int(repository.PullRequestDetails.ID), err.Error())
	}
	// Previous Fallback review comments
	commentsToDelete := getFrogbotReviewComments(comments)
	// Previous Summary comments
	for _, comment := range comments {
		if outputwriter.IsFrogbotSummaryComment(repository.OutputWriter, comment.Content) {
			commentsToDelete = append(commentsToDelete, comment)
		}
	}
	// Delete
	if len(commentsToDelete) > 0 {
		for _, commentToDelete := range commentsToDelete {
			if err = client.DeletePullRequestComment(context.Background(), prDetails.Target.Owner, prDetails.Target.Repository, int(prDetails.ID), int(commentToDelete.ID)); err != nil {
				return err
			}
		}
	}
	return err
}

func GenerateFixPullRequestDetails(vulnerabilities []formats.VulnerabilityOrViolationRow, writer outputwriter.OutputWriter) string {
	return outputwriter.GetPRSummaryContent(outputwriter.VulnerabilitiesContent(vulnerabilities, writer), true, false, writer)
}

func generatePullRequestSummaryComment(issuesCollection *IssuesCollection, writer outputwriter.OutputWriter) string {
	issuesExists := issuesCollection.IssuesExists()
	content := strings.Builder{}
	if issuesExists {
		content.WriteString(outputwriter.VulnerabilitiesContent(issuesCollection.Vulnerabilities, writer))
		content.WriteString(outputwriter.LicensesContent(issuesCollection.Licenses, writer))
	}
	return outputwriter.GetPRSummaryContent(content.String(), issuesExists, true, writer)
}

func IsFrogbotRescanComment(comment string) bool {
	return strings.Contains(strings.ToLower(comment), RescanRequestComment)
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

func addReviewComments(repo *Repository, pullRequestID int, client vcsclient.VcsClient, issues *IssuesCollection) (err error) {
	commentsToAdd := getNewReviewComments(repo, issues)
	if len(commentsToAdd) == 0 {
		return
	}
	// Add review comments for the given data
	for _, comment := range commentsToAdd {
		log.Debug("creating a review comment for", comment.Type, comment.Location.File, comment.Location.StartLine, comment.Location.StartColumn)
		if e := client.AddPullRequestReviewComments(context.Background(), repo.RepoOwner, repo.RepoName, pullRequestID, comment.CommentInfo); e != nil {
			log.Debug("couldn't add pull request review comment, fallback to regular comment: " + e.Error())
			if err = client.AddPullRequestComment(context.Background(), repo.RepoOwner, repo.RepoName, outputwriter.GetFallbackReviewCommentContent(comment.CommentInfo.Content, comment.Location, repo.OutputWriter), pullRequestID); err != nil {
				err = errors.New("couldn't add pull request  comment, fallback to comment: " + err.Error())
				return
			}
		}
	}
	return
}

// Delete existing pull request review comments (Applicable, Sast, Iac)
func DeleteExistingPullRequestReviewComments(repo *Repository, pullRequestID int, client vcsclient.VcsClient) (err error) {
	// Get all review comments in PR
	var existingComments []vcsclient.CommentInfo
	if existingComments, err = client.ListPullRequestReviewComments(context.Background(), repo.RepoOwner, repo.RepoName, pullRequestID); err != nil {
		err = errors.New("couldn't list existing review comments: " + err.Error())
		return
	}
	// Delete old review comments
	if len(existingComments) > 0 {
		if err = client.DeletePullRequestReviewComments(context.Background(), repo.RepoOwner, repo.RepoName, pullRequestID, getFrogbotReviewComments(existingComments)...); err != nil {
			err = errors.New("couldn't delete pull request review comment: " + err.Error())
			return
		}
	}
	return
}

func getFrogbotReviewComments(existingComments []vcsclient.CommentInfo) (reviewComments []vcsclient.CommentInfo) {
	for _, comment := range existingComments {
		if outputwriter.IsFrogbotReviewComment(comment.Content) {
			log.Debug("Deleting comment id:", comment.ID)
			reviewComments = append(reviewComments, comment)
		}
	}
	return
}

func getNewReviewComments(repo *Repository, issues *IssuesCollection) (commentsToAdd []ReviewComment) {
	writer := repo.OutputWriter

	for _, vulnerability := range issues.Vulnerabilities {
		for _, cve := range vulnerability.Cves {
			if cve.Applicability != nil {
				for _, evidence := range cve.Applicability.Evidence {
					commentsToAdd = append(commentsToAdd, generateReviewComment(ApplicableComment, evidence.Location, generateApplicabilityReviewContent(evidence, cve, vulnerability, writer)))
				}
			}
		}
	}
	for _, iac := range issues.Iacs {
		commentsToAdd = append(commentsToAdd, generateReviewComment(IacComment, iac.Location, generateSourceCodeReviewContent(IacComment, iac, writer)))
	}
	for _, sast := range issues.Sast {
		commentsToAdd = append(commentsToAdd, generateReviewComment(SastComment, sast.Location, generateSourceCodeReviewContent(SastComment, sast, writer)))
	}
	return
}

func generateReviewComment(commentType ReviewCommentType, location formats.Location, content string) (comment ReviewComment) {
	return ReviewComment{
		Location: location,
		CommentInfo: vcsclient.PullRequestComment{
			CommentInfo: vcsclient.CommentInfo{
				Content: content,
			},
			PullRequestDiff: createPullRequestDiff(location),
		},
		Type: commentType,
	}

}

func generateApplicabilityReviewContent(issue formats.Evidence, relatedCve formats.CveRow, relatedVulnerability formats.VulnerabilityOrViolationRow, writer outputwriter.OutputWriter) string {
	remediation := ""
	if relatedVulnerability.JfrogResearchInformation != nil {
		remediation = relatedVulnerability.JfrogResearchInformation.Remediation
	}
	return outputwriter.GenerateReviewCommentContent(outputwriter.ApplicableCveReviewContent(
		relatedVulnerability.Severity,
		issue.Reason,
		relatedCve.Applicability.ScannerDescription,
		relatedCve.Id,
		relatedVulnerability.Summary,
		fmt.Sprintf("%s:%s", relatedVulnerability.ImpactedDependencyName, relatedVulnerability.ImpactedDependencyVersion),
		remediation,
		writer,
	), writer)
}

func generateSourceCodeReviewContent(commentType ReviewCommentType, issue formats.SourceCodeRow, writer outputwriter.OutputWriter) (content string) {
	switch commentType {
	case IacComment:
		return outputwriter.GenerateReviewCommentContent(outputwriter.IacReviewContent(
			issue.Severity,
			issue.Finding,
			issue.ScannerDescription,
			writer,
		), writer)
	case SastComment:
		return outputwriter.GenerateReviewCommentContent(outputwriter.SastReviewContent(
			issue.Severity,
			issue.Finding,
			issue.ScannerDescription,
			issue.CodeFlow,
			writer,
		), writer)
	}
	return
}

func createPullRequestDiff(location formats.Location) vcsclient.PullRequestDiff {
	return vcsclient.PullRequestDiff{
		OriginalFilePath:    location.File,
		OriginalStartLine:   location.StartLine,
		OriginalEndLine:     location.EndLine,
		OriginalStartColumn: location.StartColumn,
		OriginalEndColumn:   location.EndColumn,

		NewFilePath:    location.File,
		NewStartLine:   location.StartLine,
		NewEndLine:     location.EndLine,
		NewStartColumn: location.StartColumn,
		NewEndColumn:   location.EndColumn,
	}
}
