package diff

import (
	"fmt"
	"html"
	"strings"
)

// SyncAction represents an action to synchronize data
type SyncAction struct {
	Type        SyncActionType
	Target      string
	Description string
	Data        interface{}
	Key         interface{}
	Reversible  bool
}

// SyncActionType represents the type of sync action
type SyncActionType string

const (
	SyncActionAdd    SyncActionType = "add"
	SyncActionRemove SyncActionType = "remove"
	SyncActionUpdate SyncActionType = "update"
	SyncActionNone   SyncActionType = "none"
)

// SyncStrategy defines how to handle synchronization
type SyncStrategy string

const (
	SyncStrategySourceWins SyncStrategy = "source_wins" // Source overwrites destination
	SyncStrategyDestWins   SyncStrategy = "dest_wins"   // Destination preserved
	SyncStrategyMerge      SyncStrategy = "merge"       // Merge changes
	SyncStrategyManual     SyncStrategy = "manual"      // Manual resolution required
)

// SyncPlan represents a synchronization plan
type SyncPlan struct {
	Actions    []SyncAction
	Strategy   SyncStrategy
	Statistics SyncStatistics
}

// SyncStatistics holds sync plan statistics
type SyncStatistics struct {
	TotalActions   int
	AddActions     int
	RemoveActions  int
	UpdateActions  int
	ReversibleCount int
}

// SyncGenerator generates sync actions from comparison results
type SyncGenerator struct {
	strategy     SyncStrategy
	safeMode     bool // Only generate reversible actions
	batchSize    int
	customRules  []SyncRule
}

// SyncRule defines a custom synchronization rule
type SyncRule func(diff Difference) *SyncAction

// NewSyncGenerator creates a new sync generator
func NewSyncGenerator(strategy SyncStrategy) *SyncGenerator {
	return &SyncGenerator{
		strategy:    strategy,
		safeMode:    false,
		batchSize:   100,
		customRules: []SyncRule{},
	}
}

// SafeMode enables safe mode (only reversible actions)
func (g *SyncGenerator) SafeMode(enabled bool) *SyncGenerator {
	g.safeMode = enabled
	return g
}

// SetBatchSize sets the batch size for sync operations
func (g *SyncGenerator) SetBatchSize(size int) *SyncGenerator {
	g.batchSize = size
	return g
}

// AddRule adds a custom sync rule
func (g *SyncGenerator) AddRule(rule SyncRule) *SyncGenerator {
	g.customRules = append(g.customRules, rule)
	return g
}

// GeneratePlan generates a sync plan from comparison results
func (g *SyncGenerator) GeneratePlan(result *ComparisonResult) *SyncPlan {
	plan := &SyncPlan{
		Actions:  []SyncAction{},
		Strategy: g.strategy,
	}
	
	// Apply custom rules first
	for _, diff := range result.Differences {
		handled := false
		
		for _, rule := range g.customRules {
			if action := rule(diff); action != nil {
				plan.Actions = append(plan.Actions, *action)
				handled = true
				break
			}
		}
		
		if !handled {
			// Generate default action
			if action := g.generateAction(diff); action != nil {
				plan.Actions = append(plan.Actions, *action)
			}
		}
	}
	
	// Calculate statistics
	for _, action := range plan.Actions {
		plan.Statistics.TotalActions++
		
		switch action.Type {
		case SyncActionAdd:
			plan.Statistics.AddActions++
		case SyncActionRemove:
			plan.Statistics.RemoveActions++
		case SyncActionUpdate:
			plan.Statistics.UpdateActions++
		}
		
		if action.Reversible {
			plan.Statistics.ReversibleCount++
		}
	}
	
	return plan
}

// generateAction generates a sync action for a difference
func (g *SyncGenerator) generateAction(diff Difference) *SyncAction {
	switch g.strategy {
	case SyncStrategySourceWins:
		return g.generateSourceWinsAction(diff)
	case SyncStrategyDestWins:
		return g.generateDestWinsAction(diff)
	case SyncStrategyMerge:
		return g.generateMergeAction(diff)
	default:
		return g.generateManualAction(diff)
	}
}

// generateSourceWinsAction generates action where source wins
func (g *SyncGenerator) generateSourceWinsAction(diff Difference) *SyncAction {
	switch diff.Type {
	case DiffTypeAdded:
		return &SyncAction{
			Type:        SyncActionAdd,
			Target:      diff.Path,
			Description: fmt.Sprintf("Add %s", diff.Path),
			Data:        diff.NewValue,
			Key:         diff.Key,
			Reversible:  true,
		}
		
	case DiffTypeRemoved:
		if g.safeMode {
			return nil // Don't remove in safe mode
		}
		return &SyncAction{
			Type:        SyncActionRemove,
			Target:      diff.Path,
			Description: fmt.Sprintf("Remove %s", diff.Path),
			Data:        diff.OldValue,
			Key:         diff.Key,
			Reversible:  true,
		}
		
	case DiffTypeChanged:
		return &SyncAction{
			Type:        SyncActionUpdate,
			Target:      diff.Path,
			Description: fmt.Sprintf("Update %s", diff.Path),
			Data:        diff.NewValue,
			Key:         diff.Key,
			Reversible:  true,
		}
		
	default:
		return nil
	}
}

// generateDestWinsAction generates action where destination wins
func (g *SyncGenerator) generateDestWinsAction(diff Difference) *SyncAction {
	// In dest-wins strategy, we only sync additions
	if diff.Type == DiffTypeAdded {
		return &SyncAction{
			Type:        SyncActionAdd,
			Target:      diff.Path,
			Description: fmt.Sprintf("Add %s (new item)", diff.Path),
			Data:        diff.NewValue,
			Key:         diff.Key,
			Reversible:  true,
		}
	}
	return nil
}

// generateMergeAction generates merge action
func (g *SyncGenerator) generateMergeAction(diff Difference) *SyncAction {
	switch diff.Type {
	case DiffTypeAdded:
		return &SyncAction{
			Type:        SyncActionAdd,
			Target:      diff.Path,
			Description: fmt.Sprintf("Merge: Add %s", diff.Path),
			Data:        diff.NewValue,
			Key:         diff.Key,
			Reversible:  true,
		}
		
	case DiffTypeRemoved:
		// In merge mode, mark for manual review
		return &SyncAction{
			Type:        SyncActionNone,
			Target:      diff.Path,
			Description: fmt.Sprintf("Review: %s exists in destination but not source", diff.Path),
			Data:        diff.OldValue,
			Key:         diff.Key,
			Reversible:  false,
		}
		
	case DiffTypeChanged:
		return &SyncAction{
			Type:        SyncActionUpdate,
			Target:      diff.Path,
			Description: fmt.Sprintf("Merge: Update %s", diff.Path),
			Data:        diff.NewValue,
			Key:         diff.Key,
			Reversible:  true,
		}
		
	default:
		return nil
	}
}

// generateManualAction generates manual review action
func (g *SyncGenerator) generateManualAction(diff Difference) *SyncAction {
	return &SyncAction{
		Type:        SyncActionNone,
		Target:      diff.Path,
		Description: fmt.Sprintf("Manual review required for %s", diff.Path),
		Data:        map[string]interface{}{"old": diff.OldValue, "new": diff.NewValue},
		Key:         diff.Key,
		Reversible:  false,
	}
}

// RenderPlan renders a sync plan as HTML
func RenderPlan(plan *SyncPlan) string {
	var sb strings.Builder
	
	// Summary
	sb.WriteString(`<div class="sync-plan">`)
	sb.WriteString(fmt.Sprintf(`<h3>Synchronization Plan (%s)</h3>`, plan.Strategy))
	
	// Statistics
	sb.WriteString(`<div class="sync-stats">`)
	sb.WriteString(fmt.Sprintf(`<div class="stat">Total Actions: <strong>%d</strong></div>`,
		plan.Statistics.TotalActions))
	sb.WriteString(fmt.Sprintf(`<div class="stat">Add: <strong>%d</strong></div>`,
		plan.Statistics.AddActions))
	sb.WriteString(fmt.Sprintf(`<div class="stat">Update: <strong>%d</strong></div>`,
		plan.Statistics.UpdateActions))
	sb.WriteString(fmt.Sprintf(`<div class="stat">Remove: <strong>%d</strong></div>`,
		plan.Statistics.RemoveActions))
	sb.WriteString(fmt.Sprintf(`<div class="stat">Reversible: <strong>%d</strong></div>`,
		plan.Statistics.ReversibleCount))
	sb.WriteString(`</div>`)
	
	// Actions table
	if len(plan.Actions) > 0 {
		sb.WriteString(`<table class="sync-actions-table">
			<thead>
				<tr>
					<th>Action</th>
					<th>Target</th>
					<th>Description</th>
					<th>Reversible</th>
					<th>Execute</th>
				</tr>
			</thead>
			<tbody>`)
		
		for i, action := range plan.Actions {
			actionClass := getSyncActionClass(action.Type)
			reversibleText := "No"
			if action.Reversible {
				reversibleText = "Yes"
			}
			
			sb.WriteString(fmt.Sprintf(`<tr class="%s">`, actionClass))
			sb.WriteString(fmt.Sprintf(`<td><span class="sync-action-type">%s</span></td>`,
				html.EscapeString(string(action.Type))))
			sb.WriteString(fmt.Sprintf(`<td>%s</td>`, html.EscapeString(action.Target)))
			sb.WriteString(fmt.Sprintf(`<td>%s</td>`, html.EscapeString(action.Description)))
			sb.WriteString(fmt.Sprintf(`<td>%s</td>`, reversibleText))
			sb.WriteString(fmt.Sprintf(`<td>
				<input type="checkbox" name="sync-action-%d" value="1" checked>
			</td>`, i))
			sb.WriteString(`</tr>`)
		}
		
		sb.WriteString(`</tbody></table>`)
		
		// Action buttons
		sb.WriteString(`<div class="sync-actions">
			<button class="btn btn-primary" onclick="executeSyncPlan()">Execute Selected Actions</button>
			<button class="btn btn-secondary" onclick="selectAllActions()">Select All</button>
			<button class="btn btn-secondary" onclick="deselectAllActions()">Deselect All</button>
			<button class="btn btn-secondary" onclick="exportSyncPlan()">Export Plan</button>
		</div>`)
	} else {
		sb.WriteString(`<p class="text-muted">No synchronization actions required.</p>`)
	}
	
	sb.WriteString(`</div>`)
	
	return sb.String()
}

// getSyncActionClass returns CSS class for sync action type
func getSyncActionClass(actionType SyncActionType) string {
	switch actionType {
	case SyncActionAdd:
		return "sync-add"
	case SyncActionRemove:
		return "sync-remove"
	case SyncActionUpdate:
		return "sync-update"
	default:
		return "sync-none"
	}
}

// BatchActions groups actions into batches
func (p *SyncPlan) BatchActions(batchSize int) [][]SyncAction {
	if batchSize <= 0 {
		batchSize = 100
	}
	
	var batches [][]SyncAction
	for i := 0; i < len(p.Actions); i += batchSize {
		end := i + batchSize
		if end > len(p.Actions) {
			end = len(p.Actions)
		}
		batches = append(batches, p.Actions[i:end])
	}
	
	return batches
}

// FilterByType filters actions by type
func (p *SyncPlan) FilterByType(actionType SyncActionType) []SyncAction {
	var filtered []SyncAction
	for _, action := range p.Actions {
		if action.Type == actionType {
			filtered = append(filtered, action)
		}
	}
	return filtered
}

// GetReversibleActions returns only reversible actions
func (p *SyncPlan) GetReversibleActions() []SyncAction {
	var reversible []SyncAction
	for _, action := range p.Actions {
		if action.Reversible {
			reversible = append(reversible, action)
		}
	}
	return reversible
}

// CSS returns CSS styles for sync plan rendering
func SyncPlanCSS() string {
	return `
.sync-plan {
	margin: 2rem 0;
}

.sync-stats {
	display: flex;
	gap: 2rem;
	margin: 1rem 0;
	padding: 1rem;
	background: #f8f9fa;
	border-radius: 4px;
}

.sync-stats .stat {
	font-size: 0.875rem;
}

.sync-actions-table {
	width: 100%;
	margin: 1rem 0;
}

.sync-actions-table th {
	background: #f8f9fa;
	font-weight: 600;
	text-align: left;
	padding: 0.75rem;
}

.sync-actions-table td {
	padding: 0.5rem 0.75rem;
	border-bottom: 1px solid #dee2e6;
}

.sync-action-type {
	display: inline-block;
	padding: 0.25rem 0.5rem;
	border-radius: 4px;
	font-size: 0.75rem;
	font-weight: 600;
	text-transform: uppercase;
}

.sync-add .sync-action-type {
	background: #d4edda;
	color: #155724;
}

.sync-remove .sync-action-type {
	background: #f8d7da;
	color: #721c24;
}

.sync-update .sync-action-type {
	background: #fff3cd;
	color: #856404;
}

.sync-none .sync-action-type {
	background: #e9ecef;
	color: #6c757d;
}

.sync-actions {
	margin-top: 1.5rem;
	display: flex;
	gap: 0.5rem;
}

.sync-actions .btn {
	padding: 0.5rem 1rem;
}
`
}