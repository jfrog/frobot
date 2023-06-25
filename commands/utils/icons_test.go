package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetSeverityTag(t *testing.T) {
	assert.Equal(t, "![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/applicableCriticalSeverity.png)<br>", getSeverityTag("Critical", "Undetermined"))
	assert.Equal(t, "![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/applicableHighSeverity.png)<br>", getSeverityTag("HiGh", "Undetermined"))
	assert.Equal(t, "![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/applicableMediumSeverity.png)<br>", getSeverityTag("meDium", "Undetermined"))
	assert.Equal(t, "![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/applicableLowSeverity.png)<br>", getSeverityTag("low", "Applicable"))
	assert.Equal(t, "![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/applicableUnknownSeverity.png)<br>", getSeverityTag("none", "Applicable"))
}

func TestGetSeverityTagNotApplicable(t *testing.T) {
	assert.Equal(t, "![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/notApplicableCritical.png)<br>", getSeverityTag("Critical", "Not Applicable"))
	assert.Equal(t, "![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/notApplicableHigh.png)<br>", getSeverityTag("HiGh", "Not Applicable"))
	assert.Equal(t, "![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/notApplicableMedium.png)<br>", getSeverityTag("meDium", "Not Applicable"))
	assert.Equal(t, "![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/notApplicableLow.png)<br>", getSeverityTag("low", "Not Applicable"))
	assert.Equal(t, "![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/notApplicableUnknown.png)<br>", getSeverityTag("none", "Not Applicable"))
}

func TestGetVulnerabilitiesBanners(t *testing.T) {
	assert.Equal(t, "[![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/noVulnerabilityBannerPR.png)](https://github.com/jfrog/frogbot#readme)", GetBanner(NoVulnerabilityPrBannerSource))
	assert.Equal(t, "[![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/vulnerabilitiesBannerPR.png)](https://github.com/jfrog/frogbot#readme)", GetBanner(VulnerabilitiesPrBannerSource))
	assert.Equal(t, "[![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/vulnerabilitiesBannerMR.png)](https://github.com/jfrog/frogbot#readme)", GetBanner(VulnerabilitiesMrBannerSource))
	assert.Equal(t, "[![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/noVulnerabilityBannerMR.png)](https://github.com/jfrog/frogbot#readme)", GetBanner(NoVulnerabilityMrBannerSource))
	assert.Equal(t, "[![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/vulnerabilitiesFixBannerMR.png)](https://github.com/jfrog/frogbot#readme)", GetBanner(VulnerabilitiesFixMrBannerSource))
	assert.Equal(t, "[![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/vulnerabilitiesFixBannerPR.png)](https://github.com/jfrog/frogbot#readme)", GetBanner(VulnerabilitiesFixPrBannerSource))
}

func TestGetSimplifiedTitle(t *testing.T) {
	assert.Equal(t, "**👍 Frogbot scanned this pull request and found that it did not add vulnerable dependencies.** \n", GetSimplifiedTitle(NoVulnerabilityPrBannerSource))
	assert.Equal(t, "**🚨 Frogbot scanned this pull request and found the below:**\n", GetSimplifiedTitle(VulnerabilitiesPrBannerSource))
	assert.Equal(t, "**🚨 This automated pull request was created by Frogbot and fixes the below:**\n", GetSimplifiedTitle(VulnerabilitiesFixPrBannerSource))
	assert.Equal(t, "", GetSimplifiedTitle("none"))
}
