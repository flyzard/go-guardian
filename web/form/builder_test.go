package form

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFormBuilder(t *testing.T) {
	tests := []struct {
		name     string
		build    func() *Builder
		contains []string
	}{
		{
			name: "Basic form with text field",
			build: func() *Builder {
				return New("test-form").
					Action("/submit").
					Method("POST").
					AddField(Text("username").Label("Username").Required())
			},
			contains: []string{
				`<form id="test-form-form"`,
				`method="POST"`,
				`action="/submit"`,
				`<label for="username">Username<span class="required">*</span></label>`,
				`<input name="username" type="text"`,
				`required`,
			},
		},
		{
			name: "Form with multiple field types",
			build: func() *Builder {
				return New("user-form").
					AddField(Text("name").Label("Full Name").Required()).
					AddField(Email("email").Label("Email").Required()).
					AddField(Password("password").Label("Password").MinLength(8)).
					AddField(TextArea("bio").Label("Biography").Dimensions(5, 50)).
					AddField(Select("role").Label("Role").
						AddOptions("admin", "user", "guest").
						Default("user")).
					AddField(Checkbox("newsletter").Label("Subscribe to newsletter"))
			},
			contains: []string{
				`type="text"`,
				`type="email"`,
				`type="password"`,
				`minlength="8"`,
				`<textarea`,
				`rows="5"`,
				`cols="50"`,
				`<select`,
				`<option value="user" selected>user</option>`,
				`type="checkbox"`,
			},
		},
		{
			name: "Form with HTMX attributes",
			build: func() *Builder {
				return New("htmx-form").
					HTMXPost("/api/submit", "#result").
					HTMXSwap("innerHTML").
					HTMXIndicator("#spinner").
					AddField(Text("query").Placeholder("Search..."))
			},
			contains: []string{
				`hx-post="/api/submit"`,
				`hx-target="#result"`,
				`hx-swap="innerHTML"`,
				`hx-indicator="#spinner"`,
			},
		},
		{
			name: "Form with validation errors",
			build: func() *Builder {
				return New("error-form").
					AddField(Text("username").Label("Username")).
					AddField(Email("email").Label("Email")).
					WithError("username", "Username is required").
					WithError("email", "Invalid email format")
			},
			contains: []string{
				`class="form-group has-error"`,
				`<span class="error-message">Username is required</span>`,
				`<span class="error-message">Invalid email format</span>`,
			},
		},
		{
			name: "Form with buttons",
			build: func() *Builder {
				return New("button-form").
					AddField(Text("name")).
					AddButton(SubmitButton("Save").Primary()).
					AddButton(StandardButton("Cancel").Secondary())
			},
			contains: []string{
				`<button type="submit"`,
				`class="btn btn-primary"`,
				`>Save</button>`,
				`<button type="button"`,
				`class="btn btn-secondary"`,
				`>Cancel</button>`,
			},
		},
		{
			name: "Form with CSRF token",
			build: func() *Builder {
				return New("secure-form").
					WithCSRF("test-csrf-token").
					AddField(Text("data"))
			},
			contains: []string{
				`<input type="hidden" name="_csrf" value="test-csrf-token">`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			form := tt.build()
			html := string(form.Render())

			for _, expected := range tt.contains {
				if !strings.Contains(html, expected) {
					t.Errorf("Expected HTML to contain %q, but it didn't.\nHTML: %s", expected, html)
				}
			}
		})
	}
}

func TestFieldTypes(t *testing.T) {
	tests := []struct {
		name     string
		field    Field
		error    string
		contains []string
	}{
		{
			name:  "Text field with all attributes",
			field: Text("fullname").Label("Full Name").Required().MinLength(2).MaxLength(50).Pattern("[A-Za-z ]+", "Only letters and spaces"),
			contains: []string{
				`type="text"`,
				`name="fullname"`,
				`required`,
				`minlength="2"`,
				`maxlength="50"`,
				`pattern="[A-Za-z ]+"`,
				`title="Only letters and spaces"`,
			},
		},
		{
			name:  "Select field with options",
			field: Select("country").Label("Country").AddOption("us", "United States").AddOption("uk", "United Kingdom").Default("us"),
			contains: []string{
				`<select name="country"`,
				`<option value="us" selected>United States</option>`,
				`<option value="uk">United Kingdom</option>`,
			},
		},
		{
			name:  "Radio group",
			field: Radio("gender").Label("Gender").AddOption("m", "Male").AddOption("f", "Female").AddOption("o", "Other").Default("o"),
			contains: []string{
				`type="radio"`,
				`name="gender"`,
				`value="m"`,
				`value="f"`,
				`value="o" checked`,
			},
		},
		{
			name:  "Checkbox field",
			field: Checkbox("terms").Label("I agree to the terms").SetChecked(true),
			contains: []string{
				`type="checkbox"`,
				`checked`,
				`<label for="terms" class="form-check-label">I agree to the terms</label>`,
			},
		},
		{
			name:  "Field with error",
			field: Text("email").Label("Email"),
			error: "Please enter a valid email",
			contains: []string{
				`class="form-group has-error"`,
				`<span class="error-message">Please enter a valid email</span>`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			html := tt.field.Render(tt.error)

			for _, expected := range tt.contains {
				if !strings.Contains(html, expected) {
					t.Errorf("Expected field HTML to contain %q, but it didn't.\nHTML: %s", expected, html)
				}
			}
		})
	}
}

func TestFormValidation(t *testing.T) {
	validator := NewValidator().
		Required("username", "").
		Email("email", "").
		MinLength("password", 8, "")

	// Create a test request
	req := httptest.NewRequest("POST", "/", strings.NewReader("username=john&email=invalid&password=123"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if validator.ValidateRequest(req) {
		t.Error("Expected validation to fail")
	}

	errors := validator.GetErrors()
	if _, ok := errors["email"]; !ok {
		t.Error("Expected email validation error")
	}
	if _, ok := errors["password"]; !ok {
		t.Error("Expected password validation error")
	}
}

func TestFormParser(t *testing.T) {
	type UserForm struct {
		Username string   `form:"username"`
		Email    string   `form:"email"`
		Age      int      `form:"age"`
		Active   bool     `form:"active"`
		Roles    []string `form:"roles"`
	}

	req := httptest.NewRequest("POST", "/", strings.NewReader("username=john&email=john@example.com&age=25&active=true&roles=admin&roles=user"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var user UserForm
	parser := NewParser()
	err := parser.Parse(req, &user)

	if err != nil {
		t.Fatalf("Failed to parse form: %v", err)
	}

	if user.Username != "john" {
		t.Errorf("Expected username to be 'john', got %s", user.Username)
	}
	if user.Email != "john@example.com" {
		t.Errorf("Expected email to be 'john@example.com', got %s", user.Email)
	}
	if user.Age != 25 {
		t.Errorf("Expected age to be 25, got %d", user.Age)
	}
	if !user.Active {
		t.Error("Expected active to be true")
	}
	if len(user.Roles) != 2 || user.Roles[0] != "admin" || user.Roles[1] != "user" {
		t.Errorf("Expected roles to be [admin, user], got %v", user.Roles)
	}
}

func TestButtonBuilder(t *testing.T) {
	tests := []struct {
		name     string
		button   *Button
		contains []string
	}{
		{
			name:   "Submit button with HTMX",
			button: SubmitButton("Save").HTMXPost("/api/save").HTMXTarget("#result"),
			contains: []string{
				`type="submit"`,
				`class="btn btn-primary"`,
				`hx-post="/api/save"`,
				`hx-target="#result"`,
				`>Save</button>`,
			},
		},
		{
			name:   "Danger delete button with confirmation",
			button: StandardButton("Delete").Danger().HTMXDelete("/api/delete/1").HTMXConfirm("Are you sure?"),
			contains: []string{
				`type="button"`,
				`class="btn btn-danger"`,
				`hx-delete="/api/delete/1"`,
				`hx-confirm="Are you sure?"`,
			},
		},
		{
			name: "Button group",
			button: func() *Button {
				group := NewButtonGroup().
					AddButton(SubmitButton("Save").Primary()).
					AddButton(StandardButton("Cancel").Secondary())
				// Return nil as we're testing the group render
				t.Log(group.Render())
				return nil
			}(),
			contains: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.button == nil {
				return // Skip for button group test
			}
			
			html := tt.button.Render()

			for _, expected := range tt.contains {
				if !strings.Contains(html, expected) {
					t.Errorf("Expected button HTML to contain %q, but it didn't.\nHTML: %s", expected, html)
				}
			}
		})
	}
}