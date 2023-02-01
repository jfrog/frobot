package utils

import (
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestStandardOutput_TableRow(t *testing.T) {
	var tests = []struct {
		vulnerability formats.VulnerabilityOrViolationRow
		expected      string
		name          string
	}{
		{
			name: "Single CVE and no direct dependencies",
			vulnerability: formats.VulnerabilityOrViolationRow{
				Severity:                  "Critical",
				ImpactedDependencyName:    "testdep",
				ImpactedDependencyVersion: "1.0.0",
				FixedVersions:             []string{"2.0.0"},
				Cves:                      []formats.CveRow{{Id: "CVE-2022-1234"}},
			},
			expected: "\n| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/criticalSeverity.png)<br>Critical |  |  | testdep | 1.0.0 | 2.0.0 | CVE-2022-1234 ",
		},
		{
			name: "Multiple CVEs and no direct dependencies",
			vulnerability: formats.VulnerabilityOrViolationRow{
				Severity:                  "High",
				ImpactedDependencyName:    "testdep2",
				ImpactedDependencyVersion: "1.0.0",
				FixedVersions:             []string{"2.0.0", "3.0.0"},
				Cves: []formats.CveRow{
					{Id: "CVE-2022-1234"},
					{Id: "CVE-2022-5678"},
				},
			},
			expected: "\n| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/highSeverity.png)<br>    High |  |  | testdep2 | 1.0.0 | 2.0.0<br>3.0.0 | CVE-2022-1234 ",
		},
		{
			name: "Single CVE and direct dependencies",
			vulnerability: formats.VulnerabilityOrViolationRow{
				Severity:                  "Low",
				ImpactedDependencyName:    "testdep3",
				ImpactedDependencyVersion: "1.0.0",
				FixedVersions:             []string{"2.0.0"},
				Cves:                      []formats.CveRow{{Id: "CVE-2022-1234"}},
				Components: []formats.ComponentRow{
					{Name: "dep1", Version: "1.0.0"},
					{Name: "dep2", Version: "2.0.0"},
				},
			},
			expected: "\n| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/lowSeverity.png)<br>     Low | dep1<br>dep2 | 1.0.0<br>2.0.0 | testdep3 | 1.0.0 | 2.0.0 | CVE-2022-1234 ",
		},
		{
			name: "Multiple CVEs and direct dependencies",
			vulnerability: formats.VulnerabilityOrViolationRow{
				Severity: "High",
				Cves: []formats.CveRow{
					{Id: "CVE-1"},
					{Id: "CVE-2"},
				},
				Components: []formats.ComponentRow{
					{Name: "dep1", Version: "1.0.0"},
					{Name: "dep2", Version: "2.0.0"},
				},
				ImpactedDependencyName:    "impacted",
				ImpactedDependencyVersion: "3.0.0",
				FixedVersions:             []string{"4.0.0", "5.0.0"},
			},
			expected: "\n| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/highSeverity.png)<br>    High | dep1<br>dep2 | 1.0.0<br>2.0.0 | impacted | 3.0.0 | 4.0.0<br>5.0.0 | CVE-1 ",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			smo := &StandardOutput{}
			actualOutput := smo.TableRow(tc.vulnerability)
			assert.Equal(t, tc.expected, actualOutput)
		})
	}
}

func TestStandardOutput_IsFrogbotResultComment(t *testing.T) {
	so := &StandardOutput{}

	tests := []struct {
		comment  string
		expected bool
	}{
		{
			comment:  "This is a comment with the " + GetIconTag(NoVulnerabilityBannerSource) + " icon",
			expected: true,
		},
		{
			comment:  "This is a comment with the " + GetIconTag(VulnerabilitiesBannerSource) + " icon",
			expected: true,
		},
		{
			comment:  "This is a comment with no icons",
			expected: false,
		},
	}

	for _, test := range tests {
		result := so.IsFrogbotResultComment(test.comment)
		assert.Equal(t, test.expected, result)
	}
}
