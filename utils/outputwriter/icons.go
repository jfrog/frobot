package outputwriter

import (
	"fmt"
	"strings"
)

type ImageSource string
type IconName string

const (
	baseResourceUrl = "https://raw.githubusercontent.com/jfrog/frogbot/master/resources/"

	NoVulnerabilityPrBannerSource       ImageSource = "v2/noVulnerabilityBannerPR.png"
	NoVulnerabilityMrBannerSource       ImageSource = "v2/noVulnerabilityBannerMR.png"
	VulnerabilitiesPrBannerSource       ImageSource = "v2/vulnerabilitiesBannerPR.png"
	VulnerabilitiesMrBannerSource       ImageSource = "v2/vulnerabilitiesBannerMR.png"
	VulnerabilitiesFixPrBannerSource    ImageSource = "v2/vulnerabilitiesFixBannerPR.png"
	VulnerabilitiesFixMrBannerSource    ImageSource = "v2/vulnerabilitiesFixBannerMR.png"
	criticalSeveritySource              ImageSource = "v2/applicableCriticalSeverity.png"
	notApplicableCriticalSeveritySource ImageSource = "v2/notApplicableCritical.png"
	highSeveritySource                  ImageSource = "v2/applicableHighSeverity.png"
	notApplicableHighSeveritySource     ImageSource = "v2/notApplicableHigh.png"
	mediumSeveritySource                ImageSource = "v2/applicableMediumSeverity.png"
	notApplicableMediumSeveritySource   ImageSource = "v2/notApplicableMedium.png"
	lowSeveritySource                   ImageSource = "v2/applicableLowSeverity.png"
	notApplicableLowSeveritySource      ImageSource = "v2/notApplicableLow.png"
	unknownSeveritySource               ImageSource = "v2/applicableUnknownSeverity.png"
	notApplicableUnknownSeveritySource  ImageSource = "v2/notApplicableUnknown.png"
)

func getSeverityTag(iconName IconName, applicability string) string {
	if applicability == "Not Applicable" {
		return getNotApplicableIconTags(iconName)
	}
	return getApplicableIconTags(iconName)
}

func getNotApplicableIconTags(iconName IconName) string {
	switch strings.ToLower(string(iconName)) {
	case "critical":
		return GetIconTag(notApplicableCriticalSeveritySource) + "<br>"
	case "high":
		return GetIconTag(notApplicableHighSeveritySource) + "<br>"
	case "medium":
		return GetIconTag(notApplicableMediumSeveritySource) + "<br>"
	case "low":
		return GetIconTag(notApplicableLowSeveritySource) + "<br>"
	}
	return GetIconTag(notApplicableUnknownSeveritySource) + "<br>"
}

func getApplicableIconTags(iconName IconName) string {
	switch strings.ToLower(string(iconName)) {
	case "critical":
		return GetIconTag(criticalSeveritySource) + "<br>"
	case "high":
		return GetIconTag(highSeveritySource) + "<br>"
	case "medium":
		return GetIconTag(mediumSeveritySource) + "<br>"
	case "low":
		return GetIconTag(lowSeveritySource) + "<br>"
	}
	return GetIconTag(unknownSeveritySource) + "<br>"
}

func GetBanner(banner ImageSource) string {
	return GetMarkdownCenterTag(MarkAsLink(GetIconTag(banner), FrogbotDocumentationUrl))
}

func GetIconTag(imageSource ImageSource) string {
	return fmt.Sprintf("!%s", MarkAsLink(GetSimplifiedTitle(imageSource), fmt.Sprintf("%s%s", baseResourceUrl, imageSource)))
}

func GetSimplifiedTitle(is ImageSource) string {
	switch is {
	case NoVulnerabilityPrBannerSource:
		return "👍 Frogbot scanned this pull request and found that it did not add vulnerable dependencies."
	case VulnerabilitiesPrBannerSource:
		return "🚨 Frogbot scanned this pull request and found the below:"
	case VulnerabilitiesFixPrBannerSource:
		return "🚨 This automated pull request was created by Frogbot and fixes the below:"
	case NoVulnerabilityMrBannerSource:
		return "👍 Frogbot scanned this merge request and found that it did not add vulnerable dependencies."
	case VulnerabilitiesMrBannerSource:
		return "🚨 Frogbot scanned this merge request and found the below:"
	case VulnerabilitiesFixMrBannerSource:
		return "🚨 This automated merge request was created by Frogbot and fixes the below:"
	default:
		return ""
	}
}
