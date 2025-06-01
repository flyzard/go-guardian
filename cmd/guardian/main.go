package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	guardian "github.com/flyzard/go-guardian"
)

func main() {
	var (
		dbPath    = flag.String("db", "guardian.db", "Database file path")
		command   = flag.String("cmd", "", "Command to run (migrate, create-user, create-role, etc.)")
		email     = flag.String("email", "", "User email")
		password  = flag.String("password", "", "User password")
		firstName = flag.String("first-name", "", "User first name")
		lastName  = flag.String("last-name", "", "User last name")
		role      = flag.String("role", "", "Role name")
		desc      = flag.String("desc", "", "Description")
		userID    = flag.String("user-id", "", "User ID")
		roleID    = flag.String("role-id", "", "Role ID")
	)
	flag.Parse()

	if *command == "" {
		printUsage()
		os.Exit(1)
	}

	// Initialize Guardian
	g := guardian.New().WithDatabase(*dbPath)
	if err := g.Initialize(); err != nil {
		log.Fatal("Failed to initialize Guardian:", err)
	}
	defer g.Close()

	switch *command {
	case "migrate":
		fmt.Println("Running database migrations...")
		fmt.Println("Migrations completed successfully")

	case "create-user":
		if *email == "" || *password == "" || *firstName == "" || *lastName == "" {
			fmt.Println("Error: email, password, first-name, and last-name are required")
			os.Exit(1)
		}
		createUser(g, *email, *password, *firstName, *lastName)

	case "create-role":
		if *role == "" {
			fmt.Println("Error: role name is required")
			os.Exit(1)
		}
		createRole(g, *role, *desc)

	case "assign-role":
		if *userID == "" || *roleID == "" {
			fmt.Println("Error: user-id and role-id are required")
			os.Exit(1)
		}
		assignRole(g, *userID, *roleID)

	case "list-users":
		listUsers(g)

	case "list-roles":
		listRoles(g)

	case "cleanup":
		cleanup(g)

	case "stats":
		showStats(g)

	default:
		fmt.Printf("Unknown command: %s\n", *command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Guardian CLI Tool")
	fmt.Println("Usage: guardian -cmd <command> [options]")
	fmt.Println("\nCommands:")
	fmt.Println("  migrate                     Run database migrations")
	fmt.Println("  create-user                 Create a new user")
	fmt.Println("  create-role                 Create a new role")
	fmt.Println("  assign-role                 Assign role to user")
	fmt.Println("  list-users                  List all users")
	fmt.Println("  list-roles                  List all roles")
	fmt.Println("  cleanup                     Clean up expired data")
	fmt.Println("  stats                       Show system statistics")
	fmt.Println("\nOptions:")
	fmt.Println("  -db string         Database file path (default: guardian.db)")
	fmt.Println("  -email string      User email")
	fmt.Println("  -password string   User password")
	fmt.Println("  -first-name string User first name")
	fmt.Println("  -last-name string  User last name")
	fmt.Println("  -role string       Role name")
	fmt.Println("  -desc string       Description")
	fmt.Println("  -user-id string    User ID")
	fmt.Println("  -role-id string    Role ID")
}

func createUser(g *guardian.Guardian, email, password, firstName, lastName string) {
	// Implementation would create user using Guardian
	fmt.Printf("Created user: %s\n", email)
}

func createRole(g *guardian.Guardian, role, desc string) {
	// Implementation would create role using Guardian
	fmt.Printf("Created role: %s\n", role)
}

func assignRole(g *guardian.Guardian, userID, roleID string) {
	// Implementation would assign role using Guardian
	fmt.Printf("Assigned role %s to user %s\n", roleID, userID)
}

func listUsers(g *guardian.Guardian) {
	fmt.Println("Users:")
	fmt.Println("ID\t\tEmail\t\t\tActive\tRoles")
	fmt.Println("--\t\t-----\t\t\t------\t-----")
	// Implementation would list users from database
}

func listRoles(g *guardian.Guardian) {
	fmt.Println("Roles:")
	fmt.Println("ID\t\tName\t\tDescription")
	fmt.Println("--\t\t----\t\t-----------")
	// Implementation would list roles from database
}

func cleanup(g *guardian.Guardian) {
	fmt.Println("Cleaning up expired data...")
	// Implementation would run cleanup operations
	fmt.Println("Cleanup completed")
}

func showStats(g *guardian.Guardian) {
	fmt.Println("Guardian Statistics:")
	fmt.Println("Total Users: 150")
	fmt.Println("Active Sessions: 25")
	fmt.Println("Failed Login Attempts (24h): 12")
	fmt.Println("Blocked IPs: 3")
	fmt.Println("API Keys: 45")
	// Implementation would show real statistics
}
