package diff

import (
	"fmt"
	"html"
	"strings"
	
	"github.com/flyzard/go-guardian/web/table"
)

// Renderer provides HTML rendering for comparison results
type Renderer struct {
	formatter    *table.Formatter
	showUnchanged bool
	compactMode   bool
}

// NewRenderer creates a new diff renderer
func NewRenderer() *Renderer {
	return &Renderer{
		formatter:    table.NewFormatter(),
		showUnchanged: false,
		compactMode:   false,
	}
}

// ShowUnchanged sets whether to show unchanged items
func (r *Renderer) ShowUnchanged(show bool) *Renderer {
	r.showUnchanged = show
	return r
}

// CompactMode sets compact rendering mode
func (r *Renderer) CompactMode(compact bool) *Renderer {
	r.compactMode = compact
	return r
}

// RenderSummary renders a summary of the comparison result
func (r *Renderer) RenderSummary(result *ComparisonResult) string {
	if result.IsEqual() {
		return `<div class="alert-box success">
			<span>✓</span>
			<span>Data is fully synchronized</span>
		</div>`
	}
	
	var sb strings.Builder
	sb.WriteString(`<div class="comparison-summary">`)
	
	// Overall status
	alertClass := "warning"
	if result.Statistics.RemovedCount > 0 {
		alertClass = "danger"
	}
	
	sb.WriteString(fmt.Sprintf(`<div class="alert-box %s">
		<span>⚠</span>
		<span>%s</span>
	</div>`, alertClass, html.EscapeString(result.Summary())))
	
	// Statistics cards
	sb.WriteString(`<div class="stats-grid">`)
	
	if result.Statistics.AddedCount > 0 {
		sb.WriteString(fmt.Sprintf(`<div class="stat-card added">
			<div class="stat-number">%d</div>
			<div class="stat-label">Added</div>
		</div>`, result.Statistics.AddedCount))
	}
	
	if result.Statistics.RemovedCount > 0 {
		sb.WriteString(fmt.Sprintf(`<div class="stat-card removed">
			<div class="stat-number">%d</div>
			<div class="stat-label">Removed</div>
		</div>`, result.Statistics.RemovedCount))
	}
	
	if result.Statistics.ChangedCount > 0 {
		sb.WriteString(fmt.Sprintf(`<div class="stat-card changed">
			<div class="stat-number">%d</div>
			<div class="stat-label">Changed</div>
		</div>`, result.Statistics.ChangedCount))
	}
	
	if r.showUnchanged && result.Statistics.UnchangedCount > 0 {
		sb.WriteString(fmt.Sprintf(`<div class="stat-card unchanged">
			<div class="stat-number">%d</div>
			<div class="stat-label">Unchanged</div>
		</div>`, result.Statistics.UnchangedCount))
	}
	
	sb.WriteString(`</div></div>`)
	
	return sb.String()
}

// RenderDifferences renders the differences as HTML
func (r *Renderer) RenderDifferences(result *ComparisonResult) string {
	if result.IsEqual() {
		return ""
	}
	
	var sb strings.Builder
	
	// Group differences by type
	added := []Difference{}
	removed := []Difference{}
	changed := []Difference{}
	
	for _, diff := range result.Differences {
		switch diff.Type {
		case DiffTypeAdded:
			added = append(added, diff)
		case DiffTypeRemoved:
			removed = append(removed, diff)
		case DiffTypeChanged:
			changed = append(changed, diff)
		}
	}
	
	// Render each group
	if len(removed) > 0 {
		sb.WriteString(r.renderDiffGroup("Removed Items", removed, "danger"))
	}
	
	if len(added) > 0 {
		sb.WriteString(r.renderDiffGroup("Added Items", added, "success"))
	}
	
	if len(changed) > 0 {
		sb.WriteString(r.renderDiffGroup("Changed Items", changed, "warning"))
	}
	
	return sb.String()
}

// renderDiffGroup renders a group of differences
func (r *Renderer) renderDiffGroup(title string, diffs []Difference, alertType string) string {
	var sb strings.Builder
	
	sb.WriteString(fmt.Sprintf(`<div class="diff-group">
		<h3 class="diff-group-title">%s</h3>`, html.EscapeString(title)))
	
	if r.compactMode {
		sb.WriteString(r.renderCompactDiffs(diffs, alertType))
	} else {
		sb.WriteString(r.renderDetailedDiffs(diffs, alertType))
	}
	
	sb.WriteString(`</div>`)
	
	return sb.String()
}

// renderCompactDiffs renders differences in compact mode
func (r *Renderer) renderCompactDiffs(diffs []Difference, alertType string) string {
	var sb strings.Builder
	
	sb.WriteString(`<div class="diff-list compact">`)
	
	for _, diff := range diffs {
		sb.WriteString(fmt.Sprintf(`<div class="diff-item %s">`, alertType))
		
		switch diff.Type {
		case DiffTypeAdded:
			sb.WriteString(fmt.Sprintf(`<span class="diff-path">%s</span>: `, html.EscapeString(diff.Path)))
			sb.WriteString(fmt.Sprintf(`<span class="diff-value">%v</span>`, formatValue(diff.NewValue)))
			
		case DiffTypeRemoved:
			sb.WriteString(fmt.Sprintf(`<span class="diff-path">%s</span>: `, html.EscapeString(diff.Path)))
			sb.WriteString(fmt.Sprintf(`<span class="diff-value">%v</span>`, formatValue(diff.OldValue)))
			
		case DiffTypeChanged:
			sb.WriteString(fmt.Sprintf(`<span class="diff-path">%s</span>: `, html.EscapeString(diff.Path)))
			sb.WriteString(fmt.Sprintf(`<span class="diff-old">%v</span> → `, formatValue(diff.OldValue)))
			sb.WriteString(fmt.Sprintf(`<span class="diff-new">%v</span>`, formatValue(diff.NewValue)))
		}
		
		sb.WriteString(`</div>`)
	}
	
	sb.WriteString(`</div>`)
	
	return sb.String()
}

// renderDetailedDiffs renders differences in detailed mode
func (r *Renderer) renderDetailedDiffs(diffs []Difference, alertType string) string {
	// Build table
	builder := table.New("Path", "Old Value", "New Value").
		Striped().
		Hover().
		Responsive()
	
	for _, diff := range diffs {
		oldVal := "-"
		newVal := "-"
		
		switch diff.Type {
		case DiffTypeAdded:
			newVal = formatValue(diff.NewValue)
			builder.AddRowWithClasses(
				[]string{diff.Path, oldVal, newVal},
				map[int]string{2: "text-success"},
			)
			
		case DiffTypeRemoved:
			oldVal = formatValue(diff.OldValue)
			builder.AddRowWithClasses(
				[]string{diff.Path, oldVal, newVal},
				map[int]string{1: "text-danger"},
			)
			
		case DiffTypeChanged:
			oldVal = formatValue(diff.OldValue)
			newVal = formatValue(diff.NewValue)
			builder.AddRowWithClasses(
				[]string{diff.Path, oldVal, newVal},
				map[int]string{1: "text-danger", 2: "text-success"},
			)
		}
	}
	
	return builder.Build()
}

// RenderComparison renders a side-by-side comparison
func (r *Renderer) RenderComparison(title string, oldData, newData interface{}, headers []string) string {
	var sb strings.Builder
	
	sb.WriteString(fmt.Sprintf(`<div class="comparison-section">
		<h3>%s</h3>`, html.EscapeString(title)))
	
	// Create side-by-side tables
	sb.WriteString(`<div class="comparison-tables">`)
	
	// Old data table
	sb.WriteString(`<div class="comparison-side">
		<h4>Previous State</h4>`)
	sb.WriteString(r.renderDataTable(oldData, headers, "old"))
	sb.WriteString(`</div>`)
	
	// New data table
	sb.WriteString(`<div class="comparison-side">
		<h4>Current State</h4>`)
	sb.WriteString(r.renderDataTable(newData, headers, "new"))
	sb.WriteString(`</div>`)
	
	sb.WriteString(`</div></div>`)
	
	return sb.String()
}

// renderDataTable renders data as a table
func (r *Renderer) renderDataTable(data interface{}, headers []string, tableClass string) string {
	builder := table.New(headers...).
		Striped().
		Bordered().
		Compact().
		AddClass("comparison-table").
		AddClass(tableClass)
	
	// Add data rows based on type
	// This is simplified - in production, use reflection or type assertions
	builder.AddRow("Sample data...")
	
	return builder.Build()
}

// formatValue formats a value for display
func formatValue(v interface{}) string {
	if v == nil {
		return "null"
	}
	
	switch val := v.(type) {
	case string:
		return html.EscapeString(val)
	case int, int64, float64:
		return fmt.Sprintf("%v", val)
	case bool:
		if val {
			return "true"
		}
		return "false"
	default:
		// For complex types, use a simplified representation
		return html.EscapeString(fmt.Sprintf("%v", v))
	}
}

// CSS returns the CSS styles for diff rendering
func (r *Renderer) CSS() string {
	return `
.comparison-summary {
	margin-bottom: 2rem;
}

.stats-grid {
	display: grid;
	grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
	gap: 1rem;
	margin-top: 1rem;
}

.stat-card {
	background: #f8f9fa;
	border-radius: 8px;
	padding: 1.5rem;
	text-align: center;
	border: 2px solid transparent;
}

.stat-card.added {
	border-color: #28a745;
	color: #28a745;
}

.stat-card.removed {
	border-color: #dc3545;
	color: #dc3545;
}

.stat-card.changed {
	border-color: #ffc107;
	color: #856404;
}

.stat-card.unchanged {
	border-color: #6c757d;
	color: #6c757d;
}

.stat-number {
	font-size: 2rem;
	font-weight: bold;
	line-height: 1;
}

.stat-label {
	font-size: 0.875rem;
	text-transform: uppercase;
	margin-top: 0.5rem;
}

.diff-group {
	margin-bottom: 2rem;
}

.diff-group-title {
	font-size: 1.25rem;
	margin-bottom: 1rem;
	color: #333;
}

.diff-list {
	background: #f8f9fa;
	border-radius: 4px;
	padding: 1rem;
}

.diff-item {
	padding: 0.5rem;
	margin-bottom: 0.5rem;
	border-radius: 4px;
	font-family: monospace;
	font-size: 0.875rem;
}

.diff-item.danger {
	background-color: #f8d7da;
	color: #721c24;
}

.diff-item.success {
	background-color: #d4edda;
	color: #155724;
}

.diff-item.warning {
	background-color: #fff3cd;
	color: #856404;
}

.diff-path {
	font-weight: bold;
}

.diff-old {
	color: #dc3545;
	text-decoration: line-through;
}

.diff-new {
	color: #28a745;
}

.comparison-section {
	margin-bottom: 2rem;
}

.comparison-tables {
	display: grid;
	grid-template-columns: 1fr 1fr;
	gap: 1rem;
}

@media (max-width: 768px) {
	.comparison-tables {
		grid-template-columns: 1fr;
	}
}

.comparison-side h4 {
	margin-bottom: 1rem;
	color: #495057;
}

.comparison-table {
	font-size: 0.875rem;
}

.comparison-table.old .changed {
	background-color: #f8d7da;
}

.comparison-table.new .changed {
	background-color: #d4edda;
}
`
}