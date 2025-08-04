# Go-Guardian Form Builder Framework

The Form Builder Framework provides a fluent API for building HTML forms with integrated validation, HTMX support, and CSRF protection.

## Features

- **Fluent API**: Chain methods to build forms programmatically
- **Field Types**: Text, Email, Password, TextArea, Select, Checkbox, Radio, Hidden
- **Validation**: Built-in client and server-side validation
- **HTMX Integration**: Native support for HTMX attributes
- **CSRF Protection**: Automatic CSRF token handling
- **Error Display**: Integrated error message rendering
- **Form Parsing**: Parse form data into structs automatically

## Quick Start

```go
import (
    "github.com/flyzard/go-guardian/web/form"
    "github.com/flyzard/go-guardian/web"
)

// Create a simple form
loginForm := form.New("login").
    Action("/auth/login").
    Method("POST").
    WithCSRFFromRequest(r).
    AddField(form.Email("email").
        Label("Email").
        Required().
        Placeholder("user@example.com")).
    AddField(form.Password("password").
        Label("Password").
        Required().
        MinLength(8)).
    AddButton(form.SubmitButton("Login").Primary())

// Render the form
web.NewResponse(w).HTML(loginForm.Render()).Send()
```

## Field Types

### Text Input
```go
form.Text("username").
    Label("Username").
    Required().
    MinLength(3).
    MaxLength(20).
    Pattern("^[a-zA-Z0-9]+$", "Only alphanumeric characters allowed")
```

### Email Input
```go
form.Email("email").
    Label("Email Address").
    Required().
    Placeholder("user@example.com")
```

### Password Input
```go
form.Password("password").
    Label("Password").
    Required().
    MinLength(8)
```

### TextArea
```go
form.TextArea("description").
    Label("Description").
    Dimensions(5, 50). // rows, cols
    Placeholder("Enter description...")
```

### Select Dropdown
```go
form.Select("country").
    Label("Country").
    AddOption("us", "United States").
    AddOption("uk", "United Kingdom").
    Default("us").
    Required()
```

### Checkbox
```go
form.Checkbox("agree").
    Label("I agree to the terms").
    Checked(false)
```

### Radio Group
```go
form.Radio("gender").
    Label("Gender").
    AddOption("m", "Male").
    AddOption("f", "Female").
    AddOption("o", "Other").
    Default("o")
```

### Hidden Field
```go
form.Hidden("user_id").Value("12345")
```

## HTMX Integration

The form builder has native support for HTMX attributes:

```go
searchForm := form.New("search").
    HTMXGet("/search", "#results").
    HTMXTrigger("keyup changed delay:300ms").
    HTMXIndicator("#spinner").
    AddField(form.Text("query").
        Placeholder("Search..."))
```

Available HTMX methods:
- `HTMXGet(url, target)`
- `HTMXPost(url, target)`
- `HTMXPut(url, target)`
- `HTMXDelete(url, target)`
- `HTMXSwap(mode)`
- `HTMXTrigger(trigger)`
- `HTMXIndicator(selector)`
- `HTMXConfirm(message)`
- `HTMXBoost()`
- `HTMXPushURL(value)`

## Validation

### Client-side Validation
Fields automatically include HTML5 validation attributes:

```go
form.Text("age").
    Required().
    Pattern("[0-9]+", "Please enter a valid number")
```

### Server-side Validation
Use the validator for server-side validation:

```go
// Create validator
validator := form.NewValidator().
    Required("username", "Username is required").
    Email("email", "Invalid email format").
    MinLength("password", 8, "Password too short")

// Validate request
if !validator.ValidateRequest(r) {
    // Re-render form with errors
    form.WithErrors(validator.GetErrors())
}
```

## Form Parsing

Parse form data directly into structs:

```go
type UserData struct {
    Username string   `form:"username"`
    Email    string   `form:"email"`
    Age      int      `form:"age"`
    Active   bool     `form:"active"`
    Roles    []string `form:"roles"`
}

var user UserData
err := form.BindFormData(r, &user, validator)
```

## Buttons

Add buttons with various styles:

```go
// Submit button
form.AddButton(form.SubmitButton("Save").Primary())

// Cancel button with HTMX
form.AddButton(
    form.StandardButton("Cancel").
        Secondary().
        HTMXGet("/list", "#content")
)

// Delete button with confirmation
form.AddButton(
    form.StandardButton("Delete").
        Danger().
        HTMXDelete("/api/delete").
        HTMXConfirm("Are you sure?")
)
```

Button styles:
- `Primary()`, `Secondary()`, `Success()`, `Danger()`, `Warning()`, `Info()`
- `Small()`, `Large()`, `Block()`

## Error Handling

Display validation errors:

```go
// Set individual field error
form.WithError("email", "Email already exists")

// Set multiple errors
form.WithErrors(map[string]string{
    "username": "Username is taken",
    "email": "Invalid email format",
})
```

## Live Validation Example

Implement live field validation with HTMX:

```go
form.Text("username").
    Label("Username").
    Attr("hx-post", "/validate/username").
    Attr("hx-trigger", "blur").
    Attr("hx-target", "closest .form-group")
```

## Complete Example

```go
func CreateUserForm(w http.ResponseWriter, r *http.Request) {
    // Create validator
    validator := form.NewValidator().
        Required("name", "Name is required").
        Email("email", "Invalid email").
        MinLength("password", 8, "Password must be at least 8 characters")
    
    // Create form
    userForm := form.New("create-user").
        Action("/users/create").
        Method("POST").
        WithCSRFFromRequest(r).
        HTMXPost("/api/users", "#result").
        AddField(form.Text("name").
            Label("Full Name").
            Required()).
        AddField(form.Email("email").
            Label("Email Address").
            Required()).
        AddField(form.Password("password").
            Label("Password").
            Required().
            MinLength(8)).
        AddField(form.Select("role").
            Label("Role").
            AddOptions("user", "admin").
            Default("user")).
        AddField(form.Checkbox("active").
            Label("Active").
            Checked(true)).
        AddButton(form.SubmitButton("Create User").Primary()).
        AddButton(form.StandardButton("Cancel").Secondary())
    
    if r.Method == "POST" {
        if userForm.ValidateAndBind(r, validator) {
            // Process form data
            web.NewResponse(w).Success("User created").Send()
        } else {
            // Show form with errors
            web.NewResponse(w).HTML(userForm.Render()).Send()
        }
    } else {
        // Show empty form
        web.NewResponse(w).HTML(userForm.Render()).Send()
    }
}
```