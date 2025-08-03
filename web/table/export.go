package table

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Exporter handles table data export
type Exporter struct {
	table    *Builder
	filename string
}

// NewExporter creates a new exporter
func NewExporter(table *Builder) *Exporter {
	return &Exporter{
		table:    table,
		filename: "export",
	}
}

// SetFilename sets the export filename (without extension)
func (e *Exporter) SetFilename(filename string) *Exporter {
	e.filename = filename
	return e
}

// ToCSV exports table data to CSV format
func (e *Exporter) ToCSV(w io.Writer) error {
	csvWriter := csv.NewWriter(w)
	defer csvWriter.Flush()
	
	// Write headers
	headers := make([]string, 0, len(e.table.headers))
	for _, h := range e.table.headers {
		headers = append(headers, h.Text)
	}
	if err := csvWriter.Write(headers); err != nil {
		return fmt.Errorf("failed to write headers: %w", err)
	}
	
	// Write rows
	for _, row := range e.table.rows {
		record := make([]string, 0, len(row.Cells))
		for _, cell := range row.Cells {
			// Strip HTML if present
			content := cell.Content
			if cell.IsHTML {
				content = stripHTML(content)
			}
			record = append(record, content)
		}
		if err := csvWriter.Write(record); err != nil {
			return fmt.Errorf("failed to write row: %w", err)
		}
	}
	
	return nil
}

// ToJSON exports table data to JSON format
func (e *Exporter) ToJSON(w io.Writer) error {
	// Create data structure
	data := make([]map[string]interface{}, 0, len(e.table.rows))
	
	for _, row := range e.table.rows {
		record := make(map[string]interface{})
		for i, cell := range row.Cells {
			if i < len(e.table.headers) {
				headerText := e.table.headers[i].Text
				content := cell.Content
				if cell.IsHTML {
					content = stripHTML(content)
				}
				record[headerText] = content
			}
		}
		data = append(data, record)
	}
	
	// Encode to JSON
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

// ToExcel exports table data to Excel format (simplified TSV for now)
func (e *Exporter) ToExcel(w io.Writer) error {
	// For simplicity, we'll export as TSV which Excel can open
	// In production, use a proper Excel library
	
	// Write headers
	headers := make([]string, 0, len(e.table.headers))
	for _, h := range e.table.headers {
		headers = append(headers, h.Text)
	}
	fmt.Fprintln(w, strings.Join(headers, "\t"))
	
	// Write rows
	for _, row := range e.table.rows {
		record := make([]string, 0, len(row.Cells))
		for _, cell := range row.Cells {
			content := cell.Content
			if cell.IsHTML {
				content = stripHTML(content)
			}
			// Escape tabs and newlines
			content = strings.ReplaceAll(content, "\t", " ")
			content = strings.ReplaceAll(content, "\n", " ")
			record = append(record, content)
		}
		fmt.Fprintln(w, strings.Join(record, "\t"))
	}
	
	return nil
}

// ToHTML exports table as standalone HTML document
func (e *Exporter) ToHTML(w io.Writer) error {
	// Write HTML document header
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
	<meta charset="UTF-8">
	<title>%s</title>
	<style>
		body { font-family: Arial, sans-serif; margin: 20px; }
		table { border-collapse: collapse; width: 100%%; }
		th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
		th { background-color: #f2f2f2; font-weight: bold; }
		tr:nth-child(even) { background-color: #f9f9f9; }
		.text-center { text-align: center; }
		.text-right { text-align: right; }
		.text-success { color: #28a745; }
		.text-danger { color: #dc3545; }
		.text-warning { color: #ffc107; }
		.badge { display: inline-block; padding: 0.25em 0.4em; font-size: 75%%; font-weight: 700; line-height: 1; text-align: center; white-space: nowrap; vertical-align: baseline; border-radius: 0.25rem; }
		.badge-success { color: #fff; background-color: #28a745; }
		.badge-danger { color: #fff; background-color: #dc3545; }
		.badge-warning { color: #212529; background-color: #ffc107; }
		.badge-info { color: #fff; background-color: #17a2b8; }
		.badge-secondary { color: #fff; background-color: #6c757d; }
	</style>
</head>
<body>
	<h1>%s</h1>
`, e.filename, e.filename)
	
	// Write table
	fmt.Fprint(w, e.table.Build())
	
	// Write document footer
	fmt.Fprintf(w, `
	<p style="margin-top: 20px; font-size: 0.9em; color: #666;">
		Generated on %s
	</p>
</body>
</html>`, formatCurrentTime())
	
	return nil
}

// ToMarkdown exports table as Markdown
func (e *Exporter) ToMarkdown(w io.Writer) error {
	// Write headers
	headers := make([]string, 0, len(e.table.headers))
	separators := make([]string, 0, len(e.table.headers))
	
	for _, h := range e.table.headers {
		headers = append(headers, h.Text)
		
		// Determine column alignment
		switch h.Align {
		case "left":
			separators = append(separators, ":---")
		case "right":
			separators = append(separators, "---:")
		case "center":
			separators = append(separators, ":---:")
		default:
			separators = append(separators, "---")
		}
	}
	
	fmt.Fprintf(w, "| %s |\n", strings.Join(headers, " | "))
	fmt.Fprintf(w, "| %s |\n", strings.Join(separators, " | "))
	
	// Write rows
	for _, row := range e.table.rows {
		cells := make([]string, 0, len(row.Cells))
		for _, cell := range row.Cells {
			content := cell.Content
			if cell.IsHTML {
				content = stripHTML(content)
			}
			// Escape pipe characters
			content = strings.ReplaceAll(content, "|", "\\|")
			cells = append(cells, content)
		}
		fmt.Fprintf(w, "| %s |\n", strings.Join(cells, " | "))
	}
	
	return nil
}

// ExportHandler creates an HTTP handler for table export
func ExportHandler(table *Builder, format string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		exporter := NewExporter(table)
		
		// Set filename from query parameter if provided
		if filename := r.URL.Query().Get("filename"); filename != "" {
			exporter.SetFilename(filename)
		}
		
		switch format {
		case "csv":
			w.Header().Set("Content-Type", "text/csv")
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.csv", exporter.filename))
			exporter.ToCSV(w)
			
		case "json":
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.json", exporter.filename))
			exporter.ToJSON(w)
			
		case "excel", "tsv":
			w.Header().Set("Content-Type", "text/tab-separated-values")
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.tsv", exporter.filename))
			exporter.ToExcel(w)
			
		case "html":
			w.Header().Set("Content-Type", "text/html")
			exporter.ToHTML(w)
			
		case "markdown", "md":
			w.Header().Set("Content-Type", "text/markdown")
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.md", exporter.filename))
			exporter.ToMarkdown(w)
			
		default:
			http.Error(w, "Unsupported export format", http.StatusBadRequest)
		}
	}
}

// stripHTML removes HTML tags from text (simplified version)
func stripHTML(html string) string {
	// This is a simplified version. In production, use a proper HTML parser
	// Remove common HTML entities
	text := strings.ReplaceAll(html, "&nbsp;", " ")
	text = strings.ReplaceAll(text, "&amp;", "&")
	text = strings.ReplaceAll(text, "&lt;", "<")
	text = strings.ReplaceAll(text, "&gt;", ">")
	text = strings.ReplaceAll(text, "&quot;", "\"")
	
	// Remove HTML tags
	for strings.Contains(text, "<") && strings.Contains(text, ">") {
		start := strings.Index(text, "<")
		end := strings.Index(text[start:], ">")
		if end == -1 {
			break
		}
		text = text[:start] + text[start+end+1:]
	}
	
	// Trim spaces
	return strings.TrimSpace(text)
}

// formatCurrentTime returns the current time formatted for display
func formatCurrentTime() string {
	return time.Now().Format("2006-01-02 15:04:05")
}

// BatchExporter allows exporting multiple tables at once
type BatchExporter struct {
	tables   []*Builder
	names    []string
	filename string
}

// NewBatchExporter creates a new batch exporter
func NewBatchExporter() *BatchExporter {
	return &BatchExporter{
		tables:   []*Builder{},
		names:    []string{},
		filename: "batch_export",
	}
}

// AddTable adds a table to the batch
func (be *BatchExporter) AddTable(table *Builder, name string) *BatchExporter {
	be.tables = append(be.tables, table)
	be.names = append(be.names, name)
	return be
}

// SetFilename sets the batch export filename
func (be *BatchExporter) SetFilename(filename string) *BatchExporter {
	be.filename = filename
	return be
}

// ToJSON exports all tables to a single JSON file
func (be *BatchExporter) ToJSON(w io.Writer) error {
	data := make(map[string]interface{})
	
	for i, table := range be.tables {
		name := be.names[i]
		tableData := make([]map[string]interface{}, 0, len(table.rows))
		
		for _, row := range table.rows {
			record := make(map[string]interface{})
			for j, cell := range row.Cells {
				if j < len(table.headers) {
					headerText := table.headers[j].Text
					content := cell.Content
					if cell.IsHTML {
						content = stripHTML(content)
					}
					record[headerText] = content
				}
			}
			tableData = append(tableData, record)
		}
		
		data[name] = tableData
	}
	
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}