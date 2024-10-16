package execution

import (
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestNewClient(t *testing.T) {
	rpc := "http://127.0.0.1:8080"
	state := State{}

	executionClient := &ExecutionClient{}
	executionClient, err := executionClient.New(rpc, &state)

	if err != nil {
		t.Errorf("Error in creating new client: %v", err)
	}

	assert.NotNil(t, executionClient.Rpc, "Rpc was found to be nil")
	assert.Equal(t, executionClient.state, state, "State didn't match")
}