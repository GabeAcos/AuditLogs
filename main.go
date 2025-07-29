package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/joho/godotenv"
	msgraph "github.com/microsoftgraph/msgraph-sdk-go"
	graphauditlogs "github.com/microsoftgraph/msgraph-sdk-go/auditlogs"
)

func main() {
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
		log.Fatal("Error creating a credentials")
	}

	client, err := msgraph.NewGraphServiceClientWithCredentials(cred, []string{"https://graph.microsoft.com/.default"})
	if err != nil {
		log.Fatal("Error creating a new client")
	}

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

	for _, audit := range auditLogs.GetValue() {
		fmt.Println(*audit.GetActivityDisplayName())
	}
}
