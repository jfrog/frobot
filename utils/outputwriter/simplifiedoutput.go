package outputwriter

import (
	"fmt"
	"strings"
)

const (
	simpleSeparator = ", "
)

type SimplifiedOutput struct {
	MarkdownOutput
}

func (smo *SimplifiedOutput) Separator() string {
	return simpleSeparator
}

func (smo *SimplifiedOutput) FormattedSeverity(severity, _ string) string {
	return severity
}

func (smo *SimplifiedOutput) Image(source ImageSource) string {
	return GetSimplifiedTitle(source)
}

func (smo *SimplifiedOutput) MarkInCenter(content string) string {
	return content
}

func (smo *SimplifiedOutput) MarkAsDetails(summary string, subTitleDepth int, content string) string {
	return fmt.Sprintf("%s\n%s", smo.MarkAsTitle(summary, subTitleDepth), content)
}

func (smo *SimplifiedOutput) MarkAsTitle(title string, subTitleDepth int) string {
	return fmt.Sprintf("%s\n%s %s\n%s", SectionDivider(), strings.Repeat("#", subTitleDepth), title, SectionDivider())
}
