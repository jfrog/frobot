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
	return GetIconTag(getNotApplicableIconPath(iconName)) + "<br>"
}

func getApplicableIconTags(iconName IconName) string {
	return GetIconTag(GetApplicableIconPath(iconName)) + "<br>"
}

func GetApplicableIconPath(iconName IconName) ImageSource {
	var imageSource ImageSource
	switch strings.ToLower(string(iconName)) {
	case "critical":
		imageSource = criticalSeveritySource
	case "high":
		imageSource = highSeveritySource
	case "medium":
		imageSource = mediumSeveritySource
	case "low":
		imageSource = lowSeveritySource
	default:
		imageSource = unknownSeveritySource
	}
	return getFullResourceUrl(imageSource)
}

func getNotApplicableIconPath(iconName IconName) ImageSource {
	var imageSource ImageSource
	switch strings.ToLower(string(iconName)) {
	case "critical":
		imageSource = notApplicableCriticalSeveritySource
	case "high":
		imageSource = notApplicableHighSeveritySource
	case "medium":
		imageSource = notApplicableMediumSeveritySource
	case "low":
		imageSource = notApplicableLowSeveritySource
	default:
		imageSource = notApplicableUnknownSeveritySource
	}
	return getFullResourceUrl(imageSource)
}

func getFullResourceUrl(imageSource ImageSource) ImageSource {
	return baseResourceUrl + imageSource
}

func GetBanner(banner ImageSource) string {
	formattedBanner := "[" + GetIconTag(banner) + "](https://github.com/jfrog/frogbot#readme)"
	return fmt.Sprintf("<div align='center'>\n\n%s\n\n</div>\n\n", formattedBanner)
}

func GetIconTag(imageSource ImageSource) string {
	return fmt.Sprintf("![](%s)", imageSource)
}

func GetSimplifiedTitle(is ImageSource) string {
	switch is {
	case NoVulnerabilityPrBannerSource:
		return "**👍 Frogbot scanned this pull request and found that it did not add vulnerable dependencies.** \n"
	case VulnerabilitiesPrBannerSource:
		return "**🚨 Frogbot scanned this pull request and found the below:**\n"
	case VulnerabilitiesFixPrBannerSource:
		return "**🚨 This automated pull request was created by Frogbot and fixes the below:**\n"
	default:
		return ""
	}
}
