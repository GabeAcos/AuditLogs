package main

import (
	"context"
	"encoding/csv"
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
	requestFilter := getStructuredDate()
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

	ssprfile, err := os.Create("sspr_audit_logs.csv")
	if err != nil {
		log.Fatalf("Failed to create CSV file: %v", err)
	}
	defer ssprfile.Close()

	ssprcsvwriter := csv.NewWriter(ssprfile)
	defer ssprcsvwriter.Flush()

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

	for _, audit := range auditLogs.GetValue() {
		var targetDisplayName, targetType, targetUserPrincipalName string
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
	// END OF SSPR LOG FILE CREATION

}
