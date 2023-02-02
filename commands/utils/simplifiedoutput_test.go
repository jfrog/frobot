package utils

import (
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSimplifiedOutput_TableRow(t *testing.T) {
	type testCase struct {
		name           string
		vulnerability  formats.VulnerabilityOrViolationRow
		expectedOutput string
	}

	testCases := []testCase{
		{
			name: "Single CVE and one direct dependency",
			vulnerability: formats.VulnerabilityOrViolationRow{
				Severity: "High",
				Components: []formats.ComponentRow{
					{Name: "dep1", Version: "1.0.0"},
				},
				ImpactedDependencyName:    "impacted_dep",
				ImpactedDependencyVersion: "2.0.0",
				FixedVersions:             []string{"3.0.0"},
				Cves: []formats.CveRow{
					{Id: "CVE-2022-0001"},
				},
			},
			expectedOutput: "\n| High | dep1:1.0.0 | impacted_dep | 2.0.0 | 3.0.0 | CVE-2022-0001 |",
		},
		{
			name: "No CVE and multiple direct dependencies",
			vulnerability: formats.VulnerabilityOrViolationRow{
				Severity: "Low",
				Components: []formats.ComponentRow{
					{Name: "dep1", Version: "1.0.0"},
					{Name: "dep2", Version: "2.0.0"},
				},
				ImpactedDependencyName:    "impacted_dep",
				ImpactedDependencyVersion: "3.0.0",
				FixedVersions:             []string{"4.0.0"},
				Cves:                      []formats.CveRow{},
			},
			expectedOutput: "\n| Low | dep1:1.0.0, dep2:2.0.0 | impacted_dep | 3.0.0 | 4.0.0 |  |",
		},
		{
			name: "Multiple CVEs and no direct dependencies",
			vulnerability: formats.VulnerabilityOrViolationRow{
				Severity:                  "Critical",
				Components:                []formats.ComponentRow{},
				ImpactedDependencyName:    "impacted_dep",
				ImpactedDependencyVersion: "4.0.0",
				FixedVersions:             []string{"5.0.0", "6.0.0"},
				Cves: []formats.CveRow{
					{Id: "CVE-2022-0002"},
					{Id: "CVE-2022-0003"},
				},
			},
			expectedOutput: "\n| Critical |  | impacted_dep | 4.0.0 | 5.0.0 6.0.0 | CVE-2022-0002 |",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			smo := &SimplifiedOutput{}
			actualOutput := smo.TableRow(tc.vulnerability)
			assert.Equal(t, tc.expectedOutput, actualOutput)
		})
	}
}

func TestSimplifiedOutput_IsFrogbotResultComment(t *testing.T) {
	testCases := []struct {
		name     string
		comment  string
		expected bool
	}{
		{
			name:     "Starts with No Vulnerability Banner",
			comment:  "Frogbot scanned this pull request and found that it did not add vulnerable dependencies. \n",
			expected: true,
		},
		{
			name:     "Starts with Vulnerabilities Banner",
			comment:  "Frogbot scanned this pull request and found the issues blow: \n",
			expected: true,
		},
		{
			name:     "Does not start with Banner",
			comment:  "This is a random comment.",
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			smo := &SimplifiedOutput{}
			actual := smo.IsFrogbotResultComment(tc.comment)
			assert.Equal(t, tc.expected, actual)
		})
	}
}
