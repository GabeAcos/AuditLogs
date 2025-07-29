package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/joho/godotenv"
	msgraph "github.com/microsoftgraph/msgraph-sdk-go"
	graphauditlogs "github.com/microsoftgraph/msgraph-sdk-go/auditlogs"
)

func main() {
	/* Settting up environment variables and client */
	godotenv.Load(".env.local")
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env")
	}

	clientID := os.Getenv("CLIENT_ID")
	tenantID := os.Getenv("TENANT_ID")
	clientSecret := os.Getenv("CLIENT_SECRET")

	cred, err := azidentity.NewClientSecretCredential(tenantID, clientID, clientSecret, nil)
	if err != nil {
		log.Fatal("Error creating credentials")
	}

	client, err := msgraph.NewGraphServiceClientWithCredentials(cred, []string{"https://graph.microsoft.com/.default"})
	if err != nil {
		log.Fatal("Error creating a new client")
	}

	/* Creating a filter and then retriving the audit logs for self service password resets */
	requestFilter := "activityDisplayName eq 'Reset password (self-service)' and activityDateTime ge 2025-07-23T00:00:00Z and activityDateTime le 2025-07-29T23:59:59Z"
	requestParameters := &graphauditlogs.DirectoryAuditsRequestBuilderGetQueryParameters{
		Filter: &requestFilter,
	}

	configuration := &graphauditlogs.DirectoryAuditsRequestBuilderGetRequestConfiguration{
		QueryParameters: requestParameters,
	}

	auditLogs, err := client.AuditLogs().DirectoryAudits().Get(context.Background(), configuration)
	if err != nil {
		log.Fatal("Error getting audit logs")
	}

	if auditLogs.GetValue() == nil || len(auditLogs.GetValue()) == 0 {
		fmt.Println("No audit logs found")
		return
	}

	csvfile, err := os.Create("sspr_audit_logs.csv")
	if err != nil {
		log.Fatalf("Failed to create CSV file: %v", err)
	}
	defer csvfile.Close()

	csvwriter := csv.NewWriter(csvfile)
	defer csvwriter.Flush()

	csvwriter.Write([]string{"activityDisplayName", "activityDateTime", "initiatedBy", "category", "result"})
	for _, audit := range auditLogs.GetValue() {
		row := []string{
			*audit.GetActivityDisplayName(),
			audit.GetActivityDateTime().Format("2006-01-02 15:04:05"),
			*audit.GetInitiatedBy().GetUser().GetUserPrincipalName(),
			*audit.GetCategory(),
			audit.GetResult().String(),
		}
		csvwriter.Write(row)
	}

	type AuditLogEntry struct {
		ActivityDisplayName string `json:"activityDisplayName"`
		ActivityDateTime    string `json:"activityDateTime"`
		InitiatedBy         string `json:"initiatedBy"`
		Category            string `json:"category"`
		Result              string `json:"result"`
	}

	var auditLogEntries []AuditLogEntry

	for _, audit := range auditLogs.GetValue() {
		entry := AuditLogEntry{
			ActivityDisplayName: *audit.GetActivityDisplayName(),
			ActivityDateTime:    audit.GetActivityDateTime().Format("2006-01-02 15:04:05"),
			InitiatedBy:         *audit.GetInitiatedBy().GetUser().GetUserPrincipalName(),
			Category:            *audit.GetCategory(),
			Result:              audit.GetResult().String(),
		}
		auditLogEntries = append(auditLogEntries, entry)
	}

	jsonData, err := json.MarshalIndent(auditLogEntries, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal JSON: %v", err)
	}

	jsonFile, err := os.Create("sspr_audit_logs.json")
	if err != nil {
		log.Fatalf("Failed to create JSON file: %v", err)
	}
	defer jsonFile.Close()

	_, err = jsonFile.Write(jsonData)
	if err != nil {
		log.Fatalf("Failed to write JSON data: %v", err)
	}
}
