package utils

import (
	"testing"

	"github.com/jfrog/frogbot/utils/outputwriter"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
	"github.com/stretchr/testify/assert"
)

func TestGetFrogbotReviewComments(t *testing.T) {
	testCases := []struct {
		name             string
		existingComments []vcsclient.CommentInfo
		expectedOutput   []vcsclient.CommentInfo
	}{
		{
			name: "No frogbot comments",
			existingComments: []vcsclient.CommentInfo{
				{Content: outputwriter.FrogbotTitlePrefix},
				{Content: "some comment text" + outputwriter.MarkdownComment("with hidden comment")},
				{Content: outputwriter.CommentGeneratedByFrogbot},
			},
			expectedOutput: []vcsclient.CommentInfo{},
		},
		{
			name: "With frogbot comments",
			existingComments: []vcsclient.CommentInfo{
				{Content: outputwriter.FrogbotTitlePrefix},
				{Content: outputwriter.MarkdownComment(outputwriter.ReviewCommentId) + "A Frogbot review comment"},
				{Content: "some comment text" + outputwriter.MarkdownComment("with hidden comment")},
				{Content: outputwriter.ReviewCommentId},
				{Content: outputwriter.CommentGeneratedByFrogbot},
			},
			expectedOutput: []vcsclient.CommentInfo{
				{Content: outputwriter.MarkdownComment(outputwriter.ReviewCommentId) + "A Frogbot review comment"},
				{Content: outputwriter.ReviewCommentId},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			output := getFrogbotReviewComments(tc.existingComments)
			assert.ElementsMatch(t, tc.expectedOutput, output)
		})
	}
}

func TestGetNewReviewComments(t *testing.T) {
	repo := &Repository{OutputWriter: &outputwriter.StandardOutput{}}
	testCases := []struct {
		name           string
		issues         *IssuesCollection
		expectedOutput []ReviewComment
	}{
		{
			name: "No issues for review comments",
			issues: &IssuesCollection{
				Vulnerabilities: []formats.VulnerabilityOrViolationRow{
					{
						Summary:    "summary-2",
						Applicable: "Applicable",
						IssueId:    "XRAY-2",
						ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
							SeverityDetails:        formats.SeverityDetails{Severity: "low"},
							ImpactedDependencyName: "component-C",
						},
						Cves:       []formats.CveRow{{Id: "CVE-2023-4321"}},
						Technology: coreutils.Npm,
					},
				},
				Secrets: []formats.SourceCodeRow{
					{
						SeverityDetails: formats.SeverityDetails{
							Severity:         "High",
							SeverityNumValue: 13,
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
			},
			expectedOutput: []ReviewComment{},
		},
		{
			name: "With issues for review comments",
			issues: &IssuesCollection{
				Vulnerabilities: []formats.VulnerabilityOrViolationRow{
					{
						Summary:    "summary-2",
						Applicable: "Applicable",
						IssueId:    "XRAY-2",
						ImpactedDependencyDetails: formats.ImpactedDependencyDetails{
							SeverityDetails:        formats.SeverityDetails{Severity: "Low"},
							ImpactedDependencyName: "component-C",
						},
						Cves:       []formats.CveRow{{Id: "CVE-2023-4321", Applicability: &formats.Applicability{Status: "Applicable", Evidence: []formats.Evidence{{Location: formats.Location{File: "file1", StartLine: 1, StartColumn: 10, EndLine: 2, EndColumn: 11, Snippet: "snippet"}}}}}},
						Technology: coreutils.Npm,
					},
				},
				Iacs: []formats.SourceCodeRow{
					{
						SeverityDetails: formats.SeverityDetails{
							Severity:         "High",
							SeverityNumValue: 13,
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
				Sast: []formats.SourceCodeRow{
					{
						SeverityDetails: formats.SeverityDetails{
							Severity:         "High",
							SeverityNumValue: 13,
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
			expectedOutput: []ReviewComment{
				{
					Location: formats.Location{
						File:        "file1",
						StartLine:   1,
						StartColumn: 10,
						EndLine:     2,
						EndColumn:   11,
						Snippet:     "snippet",
					},
					Type: ApplicableComment,
					CommentInfo: vcsclient.PullRequestComment{
						CommentInfo: vcsclient.CommentInfo{
							Content: outputwriter.GenerateReviewCommentContent(outputwriter.ApplicableCveReviewContent("Low", "", "", "CVE-2023-4321", "summary-2", "component-C:", "", repo.OutputWriter), repo.OutputWriter),
						},
						PullRequestDiff: vcsclient.PullRequestDiff{
							OriginalFilePath:    "file1",
							OriginalStartLine:   1,
							OriginalStartColumn: 10,
							OriginalEndLine:     2,
							OriginalEndColumn:   11,
							NewFilePath:         "file1",
							NewStartLine:        1,
							NewStartColumn:      10,
							NewEndLine:          2,
							NewEndColumn:        11,
						},
					},
				},
				{
					Location: formats.Location{
						File:        "file1",
						StartLine:   1,
						StartColumn: 10,
						EndLine:     2,
						EndColumn:   11,
						Snippet:     "aws-violation",
					},
					Type: IacComment,
					CommentInfo: vcsclient.PullRequestComment{
						CommentInfo: vcsclient.CommentInfo{
							Content: outputwriter.GenerateReviewCommentContent(outputwriter.IacReviewContent("High", "Missing auto upgrade was detected", "", repo.OutputWriter), repo.OutputWriter),
						},
						PullRequestDiff: vcsclient.PullRequestDiff{
							OriginalFilePath:    "file1",
							OriginalStartLine:   1,
							OriginalStartColumn: 10,
							OriginalEndLine:     2,
							OriginalEndColumn:   11,
							NewFilePath:         "file1",
							NewStartLine:        1,
							NewStartColumn:      10,
							NewEndLine:          2,
							NewEndColumn:        11,
						},
					},
				},
				{
					Location: formats.Location{
						File:        "file1",
						StartLine:   1,
						StartColumn: 10,
						EndLine:     2,
						EndColumn:   11,
						Snippet:     "snippet",
					},
					Type: SastComment,
					CommentInfo: vcsclient.PullRequestComment{
						CommentInfo: vcsclient.CommentInfo{
							Content: outputwriter.GenerateReviewCommentContent(outputwriter.SastReviewContent("High", "XSS Vulnerability", "", [][]formats.Location{}, repo.OutputWriter), repo.OutputWriter),
						},
						PullRequestDiff: vcsclient.PullRequestDiff{
							OriginalFilePath:    "file1",
							OriginalStartLine:   1,
							OriginalStartColumn: 10,
							OriginalEndLine:     2,
							OriginalEndColumn:   11,
							NewFilePath:         "file1",
							NewStartLine:        1,
							NewStartColumn:      10,
							NewEndLine:          2,
							NewEndColumn:        11,
						},
					},
				},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			output := getNewReviewComments(repo, tc.issues)
			assert.ElementsMatch(t, tc.expectedOutput, output)
		})
	}
}
