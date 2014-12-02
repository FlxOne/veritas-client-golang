package veritas

import (
	"fmt"
	"log"
)

type VeritasClient struct {
	customerId    int
	applicationId int
	secureToken   string
}

func NewClient(customerId int, applicationId int, secureToken string) *VeritasClient {
	return &VeritasClient{
		customerId:    customerId,
		applicationId: applicationId,
		secureToken:   secureToken,
	}
}

func (v *VeritasClient) PrintDebug() {
	log.Println(fmt.Sprintf("Veritas client (customer: %d) (app: %d)", v.customerId, v.applicationId))
}
