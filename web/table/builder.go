// Package table provides advanced HTML table building functionality
package table

import (
	"fmt"
	"html"
	"strings"
)

// Builder provides a fluent interface for building HTML tables
type Builder struct {
	headers     []Header
	rows        []Row
	classes     []string
	id          string
	caption     string
	emptyMsg    string
	responsive  bool
	sortable    bool
	filterable  bool
	paginated   bool
	pageSize    int
	currentPage int
	totalRows   int
	
	// Styling
	striped     bool
	bordered    bool
	hover       bool
	compact     bool
	
	// Features
	selectable  bool
	exportable  bool
	
	// Custom attributes
	attributes  map[string]string
}

// Header represents a table header
type Header struct {
	Text       string
	Sortable   bool
	Filterable bool
	Width      string
	Class      string
	Align      string // left, center, right
}

// Row represents a table row
type Row struct {
	Cells      []Cell
	Class      string
	ID         string
	Selectable bool
	Data       map[string]string // data-* attributes
}

// Cell represents a table cell
type Cell struct {
	Content    string
	Class      string
	Colspan    int
	Rowspan    int
	IsHTML     bool // If true, content won't be escaped
	Align      string
	Attributes map[string]string
}

// New creates a new table builder
func New(headers ...string) *Builder {
	b := &Builder{
		headers:    make([]Header, len(headers)),
		rows:       []Row{},
		classes:    []string{"table"},
		emptyMsg:   "No data available",
		attributes: make(map[string]string),
		pageSize:   25,
		currentPage: 1,
	}
	
	for i, h := range headers {
		b.headers[i] = Header{Text: h}
	}
	
	return b
}

// NewAdvanced creates a new table builder with advanced headers
func NewAdvanced(headers ...Header) *Builder {
	return &Builder{
		headers:    headers,
		rows:       []Row{},
		classes:    []string{"table"},
		emptyMsg:   "No data available",
		attributes: make(map[string]string),
		pageSize:   25,
		currentPage: 1,
	}
}

// AddHeader adds a header to the table
func (b *Builder) AddHeader(text string) *Builder {
	b.headers = append(b.headers, Header{Text: text})
	return b
}

// AddAdvancedHeader adds an advanced header to the table
func (b *Builder) AddAdvancedHeader(header Header) *Builder {
	b.headers = append(b.headers, header)
	return b
}

// AddRow adds a simple row to the table
func (b *Builder) AddRow(cells ...string) *Builder {
	row := Row{
		Cells: make([]Cell, len(cells)),
	}
	
	for i, content := range cells {
		row.Cells[i] = Cell{Content: content}
	}
	
	b.rows = append(b.rows, row)
	b.totalRows++
	return b
}

// AddHTMLRow adds a row with HTML content
func (b *Builder) AddHTMLRow(cells ...string) *Builder {
	row := Row{
		Cells: make([]Cell, len(cells)),
	}
	
	for i, content := range cells {
		row.Cells[i] = Cell{Content: content, IsHTML: true}
	}
	
	b.rows = append(b.rows, row)
	b.totalRows++
	return b
}

// AddAdvancedRow adds an advanced row to the table
func (b *Builder) AddAdvancedRow(row Row) *Builder {
	b.rows = append(b.rows, row)
	b.totalRows++
	return b
}

// AddRowWithClasses adds a row with specific cell classes
func (b *Builder) AddRowWithClasses(cells []string, cellClasses map[int]string) *Builder {
	row := Row{
		Cells: make([]Cell, len(cells)),
	}
	
	for i, content := range cells {
		cell := Cell{Content: content}
		if class, ok := cellClasses[i]; ok {
			cell.Class = class
		}
		row.Cells[i] = cell
	}
	
	b.rows = append(b.rows, row)
	b.totalRows++
	return b
}

// EmptyRow adds an empty row with a message
func (b *Builder) EmptyRow(message string, colspan int) *Builder {
	b.rows = append(b.rows, Row{
		Cells: []Cell{{
			Content: message,
			Colspan: colspan,
			Class:   "text-center text-muted",
		}},
	})
	return b
}

// SetID sets the table ID
func (b *Builder) SetID(id string) *Builder {
	b.id = id
	return b
}

// SetCaption sets the table caption
func (b *Builder) SetCaption(caption string) *Builder {
	b.caption = caption
	return b
}

// SetEmptyMessage sets the message shown when table is empty
func (b *Builder) SetEmptyMessage(msg string) *Builder {
	b.emptyMsg = msg
	return b
}

// AddClass adds a CSS class to the table
func (b *Builder) AddClass(class string) *Builder {
	b.classes = append(b.classes, class)
	return b
}

// Responsive makes the table responsive
func (b *Builder) Responsive() *Builder {
	b.responsive = true
	return b
}

// Sortable makes the table sortable
func (b *Builder) Sortable() *Builder {
	b.sortable = true
	return b
}

// Filterable makes the table filterable
func (b *Builder) Filterable() *Builder {
	b.filterable = true
	return b
}

// Paginated enables pagination
func (b *Builder) Paginated(pageSize int) *Builder {
	b.paginated = true
	b.pageSize = pageSize
	return b
}

// SetPage sets the current page
func (b *Builder) SetPage(page int) *Builder {
	b.currentPage = page
	return b
}

// Striped adds striped styling
func (b *Builder) Striped() *Builder {
	b.striped = true
	b.AddClass("table-striped")
	return b
}

// Bordered adds borders
func (b *Builder) Bordered() *Builder {
	b.bordered = true
	b.AddClass("table-bordered")
	return b
}

// Hover adds hover effect
func (b *Builder) Hover() *Builder {
	b.hover = true
	b.AddClass("table-hover")
	return b
}

// Compact makes the table compact
func (b *Builder) Compact() *Builder {
	b.compact = true
	b.AddClass("table-sm")
	return b
}

// Selectable makes rows selectable
func (b *Builder) Selectable() *Builder {
	b.selectable = true
	return b
}

// Exportable adds export functionality
func (b *Builder) Exportable() *Builder {
	b.exportable = true
	return b
}

// SetAttribute sets a custom attribute
func (b *Builder) SetAttribute(key, value string) *Builder {
	b.attributes[key] = value
	return b
}

// Build generates the HTML table
func (b *Builder) Build() string {
	var sb strings.Builder
	
	// Wrap in responsive container if needed
	if b.responsive {
		sb.WriteString(`<div class="table-responsive">`)
	}
	
	// Start table
	sb.WriteString(`<table`)
	
	// Add ID
	if b.id != "" {
		sb.WriteString(fmt.Sprintf(` id="%s"`, html.EscapeString(b.id)))
	}
	
	// Add classes
	if len(b.classes) > 0 {
		sb.WriteString(fmt.Sprintf(` class="%s"`, strings.Join(b.classes, " ")))
	}
	
	// Add custom attributes
	for key, value := range b.attributes {
		sb.WriteString(fmt.Sprintf(` %s="%s"`, key, html.EscapeString(value)))
	}
	
	// Add data attributes for features
	if b.sortable {
		sb.WriteString(` data-sortable="true"`)
	}
	if b.filterable {
		sb.WriteString(` data-filterable="true"`)
	}
	if b.paginated {
		sb.WriteString(fmt.Sprintf(` data-page-size="%d"`, b.pageSize))
	}
	
	sb.WriteString(`>`)
	
	// Add caption
	if b.caption != "" {
		sb.WriteString(fmt.Sprintf(`<caption>%s</caption>`, html.EscapeString(b.caption)))
	}
	
	// Build header
	if len(b.headers) > 0 {
		sb.WriteString(`<thead><tr>`)
		
		// Add select all checkbox if selectable
		if b.selectable {
			sb.WriteString(`<th class="select-column"><input type="checkbox" class="select-all"></th>`)
		}
		
		for _, header := range b.headers {
			sb.WriteString(`<th`)
			
			if header.Width != "" {
				sb.WriteString(fmt.Sprintf(` width="%s"`, header.Width))
			}
			
			if header.Class != "" {
				sb.WriteString(fmt.Sprintf(` class="%s"`, header.Class))
			}
			
			if header.Align != "" {
				sb.WriteString(fmt.Sprintf(` class="text-%s"`, header.Align))
			}
			
			if b.sortable && header.Sortable {
				sb.WriteString(` data-sortable="true"`)
			}
			
			if b.filterable && header.Filterable {
				sb.WriteString(` data-filterable="true"`)
			}
			
			sb.WriteString(`>`)
			sb.WriteString(html.EscapeString(header.Text))
			
			// Add sort indicators
			if b.sortable && header.Sortable {
				sb.WriteString(` <span class="sort-indicator"></span>`)
			}
			
			sb.WriteString(`</th>`)
		}
		
		sb.WriteString(`</tr></thead>`)
	}
	
	// Build body
	sb.WriteString(`<tbody>`)
	
	if len(b.rows) == 0 {
		// Show empty message
		colspan := len(b.headers)
		if b.selectable {
			colspan++
		}
		sb.WriteString(fmt.Sprintf(`<tr><td colspan="%d" class="text-center text-muted">%s</td></tr>`, 
			colspan, html.EscapeString(b.emptyMsg)))
	} else {
		// Calculate pagination
		startIdx := 0
		endIdx := len(b.rows)
		
		if b.paginated {
			startIdx = (b.currentPage - 1) * b.pageSize
			endIdx = startIdx + b.pageSize
			if endIdx > len(b.rows) {
				endIdx = len(b.rows)
			}
		}
		
		// Render rows
		for i := startIdx; i < endIdx; i++ {
			row := b.rows[i]
			sb.WriteString(`<tr`)
			
			if row.ID != "" {
				sb.WriteString(fmt.Sprintf(` id="%s"`, html.EscapeString(row.ID)))
			}
			
			if row.Class != "" {
				sb.WriteString(fmt.Sprintf(` class="%s"`, row.Class))
			}
			
			// Add data attributes
			for key, value := range row.Data {
				sb.WriteString(fmt.Sprintf(` data-%s="%s"`, key, html.EscapeString(value)))
			}
			
			sb.WriteString(`>`)
			
			// Add select checkbox if selectable
			if b.selectable && row.Selectable {
				sb.WriteString(`<td class="select-column"><input type="checkbox" class="select-row"></td>`)
			} else if b.selectable {
				sb.WriteString(`<td class="select-column"></td>`)
			}
			
			// Render cells
			for _, cell := range row.Cells {
				sb.WriteString(`<td`)
				
				if cell.Class != "" {
					sb.WriteString(fmt.Sprintf(` class="%s"`, cell.Class))
				}
				
				if cell.Colspan > 1 {
					sb.WriteString(fmt.Sprintf(` colspan="%d"`, cell.Colspan))
				}
				
				if cell.Rowspan > 1 {
					sb.WriteString(fmt.Sprintf(` rowspan="%d"`, cell.Rowspan))
				}
				
				if cell.Align != "" {
					sb.WriteString(fmt.Sprintf(` class="text-%s"`, cell.Align))
				}
				
				// Add cell attributes
				for key, value := range cell.Attributes {
					sb.WriteString(fmt.Sprintf(` %s="%s"`, key, html.EscapeString(value)))
				}
				
				sb.WriteString(`>`)
				
				if cell.IsHTML {
					sb.WriteString(cell.Content)
				} else {
					sb.WriteString(html.EscapeString(cell.Content))
				}
				
				sb.WriteString(`</td>`)
			}
			
			sb.WriteString(`</tr>`)
		}
	}
	
	sb.WriteString(`</tbody>`)
	
	// Add footer if needed (for pagination, export, etc.)
	if b.paginated || b.exportable {
		sb.WriteString(`<tfoot><tr><td colspan="`)
		colspan := len(b.headers)
		if b.selectable {
			colspan++
		}
		sb.WriteString(fmt.Sprintf(`%d">`, colspan))
		
		// Add pagination controls
		if b.paginated && b.totalRows > b.pageSize {
			sb.WriteString(b.buildPagination())
		}
		
		// Add export buttons
		if b.exportable {
			sb.WriteString(b.buildExportButtons())
		}
		
		sb.WriteString(`</td></tr></tfoot>`)
	}
	
	sb.WriteString(`</table>`)
	
	// Close responsive wrapper
	if b.responsive {
		sb.WriteString(`</div>`)
	}
	
	return sb.String()
}

// buildPagination builds pagination controls
func (b *Builder) buildPagination() string {
	totalPages := (b.totalRows + b.pageSize - 1) / b.pageSize
	
	var sb strings.Builder
	sb.WriteString(`<div class="table-pagination">`)
	sb.WriteString(fmt.Sprintf(`<span>Page %d of %d</span>`, b.currentPage, totalPages))
	sb.WriteString(`<div class="pagination-controls">`)
	
	// Previous button
	if b.currentPage > 1 {
		sb.WriteString(`<button class="btn btn-sm" data-page="`)
		sb.WriteString(fmt.Sprintf(`%d">Previous</button>`, b.currentPage-1))
	}
	
	// Page numbers
	for i := 1; i <= totalPages; i++ {
		if i == b.currentPage {
			sb.WriteString(fmt.Sprintf(`<span class="current-page">%d</span>`, i))
		} else {
			sb.WriteString(fmt.Sprintf(`<button class="btn btn-sm" data-page="%d">%d</button>`, i, i))
		}
	}
	
	// Next button
	if b.currentPage < totalPages {
		sb.WriteString(`<button class="btn btn-sm" data-page="`)
		sb.WriteString(fmt.Sprintf(`%d">Next</button>`, b.currentPage+1))
	}
	
	sb.WriteString(`</div></div>`)
	return sb.String()
}

// buildExportButtons builds export buttons
func (b *Builder) buildExportButtons() string {
	return `<div class="table-export">
		<button class="btn btn-sm export-csv">Export CSV</button>
		<button class="btn btn-sm export-excel">Export Excel</button>
		<button class="btn btn-sm export-pdf">Export PDF</button>
	</div>`
}