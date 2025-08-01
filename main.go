package main

import (
	"context"
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/joho/godotenv"
	msgraph "github.com/microsoftgraph/msgraph-sdk-go"
	graphauditlogs "github.com/microsoftgraph/msgraph-sdk-go/auditlogs"
	graphrolemanagement "github.com/microsoftgraph/msgraph-sdk-go/rolemanagement"
)

func main() {
	// Load environment variables from .env.local and then .env file
	godotenv.Load(".env.local")
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env")
	}

	// Retrieve credentials from environment variables
	clientID := os.Getenv("CLIENT_ID")
	tenantID := os.Getenv("TENANT_ID")
	clientSecret := os.Getenv("CLIENT_SECRET")

	// Create Azure identity credential using client secret authentication
	cred, err := azidentity.NewClientSecretCredential(tenantID, clientID, clientSecret, nil)
	if err != nil {
		log.Fatal("Error creating credentials")
	}

	// Create Microsoft Graph client using the provided credentials
	client, err := msgraph.NewGraphServiceClientWithCredentials(cred, []string{"https://graph.microsoft.com/.default"})
	if err != nil {
		log.Fatal("Error creating a new client")
	}

	// ---------------------------
	// SSPR AUDIT LOG RETRIEVAL
	// ---------------------------

	// Define time range: from one week ago to today in UTC
	currentTime := time.Now().UTC().Format("2006-01-02T00:00:00Z")
	aWeekAgo := time.Now().UTC().Add(-168 * time.Hour).Format("2006-01-02T00:00:00Z")

	// Create filter for SSPR (self-service password reset) audit logs
	date := "activityDisplayName eq 'Reset password (self-service)' and activityDateTime ge " + aWeekAgo + " and activityDateTime le " + currentTime

	// Define request parameters using the filter
	requestParameters := &graphauditlogs.DirectoryAuditsRequestBuilderGetQueryParameters{
		Filter: &date,
	}
	configuration := &graphauditlogs.DirectoryAuditsRequestBuilderGetRequestConfiguration{
		QueryParameters: requestParameters,
	}

	// Retrieve the filtered audit logs
	auditLogs, err := client.AuditLogs().DirectoryAudits().Get(context.Background(), configuration)
	if err != nil {
		log.Fatal("Error getting audit logs")
	}

	// If no logs are returned, exit early
	if auditLogs.GetValue() == nil || len(auditLogs.GetValue()) == 0 {
		fmt.Println("No audit logs found")
		return
	}

	// Create CSV file to store SSPR logs
	ssprfile, err := os.Create("sspr_audit_logs.csv")
	if err != nil {
		log.Fatalf("Failed to create CSV file: %v", err)
	}
	defer ssprfile.Close()

	ssprcsvwriter := csv.NewWriter(ssprfile)
	defer ssprcsvwriter.Flush()

	// Write header row to CSV
	ssprcsvwriter.Write([]string{
		"Date (UTC)",
		"CorrelationId",
		"Service",
		"Category",
		"Activity",
		"Result",
		"ResultReason",
		"ActorType",
		"ActorObjectId",
		"ActorUserPrincipalname",
		"Target1Type",
		"Target1DisplayName",
		"Target1UserPrincipalName",
		"Target3ModifiedProperty5OldValue",
		"Target3ModifiedProperty5NewValue",
		"AdditionalDetail1Key",
		"AdditionalDetail1Value",
	})

	// Loop through each audit log entry and extract details
	for _, audit := range auditLogs.GetValue() {
		var targetDisplayName, targetType, targetUserPrincipalName string

		// Extract target resource info if available
		targetResources := audit.GetTargetResources()
		if len(targetResources) > 0 {
			target := targetResources[0]
			if target.GetDisplayName() != nil {
				targetDisplayName = *target.GetDisplayName()
			}
			if target.GetGroupType() != nil {
				targetType = *target.GetTypeEscaped()
			}
			if target.GetUserPrincipalName() != nil {
				targetUserPrincipalName = *target.GetUserPrincipalName()
			}
		}

		// Extract additional details if available
		var additionalDetail1Key, additionalDetail1Value string
		additionalDetails := audit.GetAdditionalDetails()
		if len(additionalDetails) > 0 {
			if additionalDetails[0].GetKey() != nil {
				additionalDetail1Key = *additionalDetails[0].GetKey()
			}
			if additionalDetails[0].GetValue() != nil {
				additionalDetail1Value = *additionalDetails[0].GetValue()
			}
		}

		// Create a row of log data for the CSV file
		row := []string{
			audit.GetActivityDateTime().Format("2006-01-02 15:04:05"),
			*audit.GetCorrelationId(),
			*audit.GetLoggedByService(),
			*audit.GetCategory(),
			*audit.GetActivityDisplayName(),
			audit.GetResult().String(),
			*audit.GetResultReason(),
			*audit.GetInitiatedBy().GetUser().GetOdataType(),
			*audit.GetInitiatedBy().GetUser().GetId(),
			*audit.GetInitiatedBy().GetUser().GetUserPrincipalName(),
			targetType,
			targetDisplayName,
			targetUserPrincipalName,
			additionalDetail1Key,
			additionalDetail1Value,
		}
		ssprcsvwriter.Write(row)
	}

	// ---------------------------
	// ROLE ASSIGNMENT RETRIEVAL
	// ---------------------------

	// Prepare query to expand the 'principal' object in role assignments
	rolesRequestParameters := &graphrolemanagement.DirectoryRoleAssignmentsRequestBuilderGetQueryParameters{
		Expand: []string{"principal"},
	}
	rolesConfiguration := &graphrolemanagement.DirectoryRoleAssignmentsRequestBuilderGetRequestConfiguration{
		QueryParameters: rolesRequestParameters,
	}

	// Get role assignments from Microsoft Graph
	roleAssignments, err := client.RoleManagement().Directory().RoleAssignments().Get(context.Background(), rolesConfiguration)
	if err != nil {
		log.Fatalf("Error getting role assignments log: %v", err)
	}

	if roleAssignments.GetValue() == nil || len(roleAssignments.GetValue()) == 0 {
		log.Fatal("No role assignment logs found")
	}

	// Create CSV file for role assignments
	rolefile, err := os.Create("role_assignment_logs.csv")
	if err != nil {
		log.Fatalf("Failed to create CSV file: %v", err)
	}
	defer rolefile.Close()

	rolecsvwriter := csv.NewWriter(rolefile)
	defer rolecsvwriter.Flush()

	// Write header row to role assignment CSV
	rolecsvwriter.Write([]string{
		"Role Name",
		"Name",
		"Email",
		"Type",
	})

	// Iterate over each role assignment
	for _, role := range roleAssignments.GetValue() {
		var (
			principalId, principalType string
			name, email, roleName      string
		)

		// If the assignment has a principal, attempt to retrieve user or service principal info
		if role.GetPrincipal() != nil {
			if role.GetPrincipal().GetId() != nil {
				principalId = *role.GetPrincipal().GetId()
				err = nil

				// Try fetching user info by principal ID
				user, err := client.Users().ByUserId(principalId).Get(context.Background(), nil)
				if err != nil {
					// If not a user, try fetching service principal (enterprise app)
					servicePrincipals, err := client.ServicePrincipals().ByServicePrincipalId(principalId).Get(context.Background(), nil)
					if err != nil {
						log.Print(err)
						log.Fatalf("Could not find an enterprise app with id of %v", principalId)
					}
					name = safeString(servicePrincipals.GetDisplayName())
					email = ""
					fmt.Println("Boop") // Debug message
				} else {
					name = safeString(user.GetDisplayName())
					email = safeString(user.GetMail())
					fmt.Println("Beep") // Debug message
				}
			}

			// Determine principal type (User or Enterprise App)
			if role.GetPrincipal().GetOdataType() != nil {
				principalType = *role.GetPrincipal().GetOdataType()
				switch principalType {
				case "#microsoft.graph.servicePrincipal":
					principalType = "Enterprise Application"
				case "#microsoft.graph.user":
					principalType = "User"
				default:
					principalType = ""
				}
			}
		}

		// Retrieve role definition to get the role name
		roleDefinitionId := safeString(role.GetRoleDefinitionId())
		roleDefinitions, err := client.RoleManagement().Directory().RoleDefinitions().ByUnifiedRoleDefinitionId(roleDefinitionId).Get(context.Background(), nil)
		if err != nil {
			log.Fatal(err)
		}
		roleName = safeString(roleDefinitions.GetDisplayName())

		// Write role assignment info to CSV
		row := []string{
			roleName,
			name,
			email,
			principalType,
		}
		rolecsvwriter.Write(row)
	}

	fmt.Println("All done!") // Final message
}

// safeString is a helper function to safely dereference string pointers
func safeString(ptr *string) string {
	if ptr != nil {
		return *ptr
	}
	return ""
}
