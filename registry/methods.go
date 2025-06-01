package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	"github.com/bsv-blockchain/go-sdk/overlay/topic"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/transaction/template/pushdrop"
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// RegisterDefinition publishes a new on-chain definition for baskets, protocols, or certificates.
// The definition data is encoded in a pushdrop-based UTXO.
func (c *RegistryClient) RegisterDefinition(ctx context.Context, data DefinitionData) (*RegisterDefinitionResult, error) {
	// Get the registry operator's public key
	pubKeyResult, err := c.wallet.GetPublicKey(ctx, wallet.GetPublicKeyArgs{
		IdentityKey: true,
	}, c.originator)
	if err != nil {
		return nil, fmt.Errorf("failed to get identity public key: %w", err)
	}
	registryOperator := fmt.Sprintf("%x", pubKeyResult.PublicKey.Compressed())

	// Create a PushDrop template
	pushDropTemplate := &pushdrop.PushDropTemplate{
		Wallet:     c.wallet,
		Originator: c.originator,
	}

	// Convert definition data into PushDrop fields
	fields, err := buildPushDropFields(data, registryOperator)
	if err != nil {
		return nil, fmt.Errorf("failed to build push drop fields: %w", err)
	}

	// Convert the user-friendly definitionType to the actual wallet protocol
	protocol := mapDefinitionTypeToWalletProtocol(data.GetDefinitionType())

	// Lock the fields into a pushdrop-based UTXO
	lockingScript, err := pushDropTemplate.Lock(
		ctx,
		fields,
		protocol,
		"1",
		wallet.Counterparty{
			Type: wallet.CounterpartyTypeAnyone,
		},
		false,
		true,
		true, // lockPosBefore
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create locking script: %w", err)
	}

	// Create a transaction
	randomizeOutputs := false
	createResult, err := c.wallet.CreateAction(ctx, wallet.CreateActionArgs{
		Description: fmt.Sprintf("Register a new %s item", data.GetDefinitionType()),
		Outputs: []wallet.CreateActionOutput{
			{
				Satoshis:          RegistrantTokenAmount,
				LockingScript:     lockingScript.Bytes(),
				OutputDescription: fmt.Sprintf("New %s registration token", data.GetDefinitionType()),
				Basket:            mapDefinitionTypeToBasketName(data.GetDefinitionType()),
			},
		},
		Options: &wallet.CreateActionOptions{
			RandomizeOutputs: &randomizeOutputs,
		},
	}, c.originator)
	if err != nil {
		return nil, fmt.Errorf("failed to create transaction: %w", err)
	}

	if createResult.Tx == nil {
		return nil, fmt.Errorf("failed to create %s registration transaction", data.GetDefinitionType())
	}

	// Get the network if not already set
	if c.network < overlay.NetworkMainnet || c.network > overlay.NetworkLocal {
		networkResult, err := c.wallet.GetNetwork(ctx, struct{}{}, c.originator)
		if err != nil {
			return nil, fmt.Errorf("failed to get network: %w", err)
		}
		switch networkResult.Network {
		case "mainnet":
			c.network = overlay.NetworkMainnet
		case "testnet":
			c.network = overlay.NetworkTestnet
		default:
			c.network = overlay.NetworkLocal
		}
	}

	// Broadcast to the relevant topic
	broadcaster, err := c.broadcasterFactory(
		[]string{mapDefinitionTypeToTopic(data.GetDefinitionType())},
		&topic.BroadcasterConfig{
			NetworkPreset: c.network,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create broadcaster: %w", err)
	}

	tx, err := transaction.NewTransactionFromBEEF(createResult.Tx)
	if err != nil {
		return nil, fmt.Errorf("failed to create transaction from BEEF: %w", err)
	}

	success, failure := broadcaster.BroadcastCtx(ctx, tx)
	return &RegisterDefinitionResult{
		Success: success,
		Failure: failure,
	}, nil
}

// ResolveBasket resolves basket registry entries using a lookup service.
func (c *RegistryClient) ResolveBasket(ctx context.Context, query BasketQuery) ([]*BasketDefinitionData, error) {
	fmt.Println("DEBUG: Starting ResolveBasket")
	resolver := c.lookupFactory()
	fmt.Println("DEBUG: Got lookup resolver")
	serviceName := mapDefinitionTypeToServiceName(DefinitionTypeBasket)
	fmt.Printf("DEBUG: Service name: %s\n", serviceName)

	// Prepare the lookup query
	queryJSON, err := json.Marshal(query)
	if err != nil {
		fmt.Printf("DEBUG: Error marshalling query: %v\n", err)
		return nil, fmt.Errorf("error marshalling query: %w", err)
	}
	fmt.Printf("DEBUG: Query JSON: %s\n", string(queryJSON))

	// Make the lookup query
	fmt.Println("DEBUG: About to call resolver.Query")
	result, err := resolver.Query(ctx, &lookup.LookupQuestion{
		Service: serviceName,
		Query:   queryJSON,
	})
	fmt.Println("DEBUG: Resolver.Query completed")
	if err != nil {
		fmt.Printf("DEBUG: Lookup query error: %v\n", err)
		return nil, fmt.Errorf("lookup query error: %w", err)
	}

	fmt.Printf("DEBUG: Result type: %s\n", result.Type)
	if result.Type != lookup.AnswerTypeOutputList {
		fmt.Println("DEBUG: Unexpected lookup result type")
		return nil, errors.New("unexpected lookup result type")
	}

	fmt.Printf("DEBUG: Outputs count: %d\n", len(result.Outputs))
	parsedRecords := make([]*BasketDefinitionData, 0)
	for i, output := range result.Outputs {
		fmt.Printf("DEBUG: Processing output %d\n", i)
		tx, err := transaction.NewTransactionFromBEEF(output.Beef)
		if err != nil {
			fmt.Printf("DEBUG: Error parsing transaction from BEEF: %v\n", err)
			continue // Skip invalid transactions
		}
		fmt.Printf("DEBUG: Parsed transaction with %d outputs\n", len(tx.Outputs))

		if int(output.OutputIndex) >= len(tx.Outputs) {
			fmt.Printf("DEBUG: Output index %d out of range (max %d)\n", output.OutputIndex, len(tx.Outputs)-1)
			continue
		}

		lockingScript := tx.Outputs[output.OutputIndex].LockingScript
		fmt.Printf("DEBUG: Got locking script of length %d\n", len(lockingScript.Bytes()))

		record, err := parseLockingScript(DefinitionTypeBasket, lockingScript)
		if err != nil {
			fmt.Printf("DEBUG: Error parsing locking script: %v\n", err)
			continue // Skip invalid records
		}
		fmt.Println("DEBUG: Successfully parsed locking script")

		if basketRecord, ok := record.(*BasketDefinitionData); ok {
			fmt.Printf("DEBUG: Adding basket record: %s\n", basketRecord.BasketID)
			parsedRecords = append(parsedRecords, basketRecord)
		} else {
			fmt.Printf("DEBUG: Record is not a BasketDefinitionData, type: %T\n", record)
		}
	}

	fmt.Printf("DEBUG: Returning %d parsed records\n", len(parsedRecords))
	return parsedRecords, nil
}

// ResolveProtocol resolves protocol registry entries using a lookup service.
func (c *RegistryClient) ResolveProtocol(ctx context.Context, query ProtocolQuery) ([]*ProtocolDefinitionData, error) {
	resolver := c.lookupFactory()
	serviceName := mapDefinitionTypeToServiceName(DefinitionTypeProtocol)

	// Prepare the lookup query
	queryJSON, err := json.Marshal(query)
	if err != nil {
		return nil, fmt.Errorf("error marshalling query: %w", err)
	}

	// Make the lookup query
	result, err := resolver.Query(ctx, &lookup.LookupQuestion{
		Service: serviceName,
		Query:   queryJSON,
	})
	if err != nil {
		return nil, fmt.Errorf("lookup query error: %w", err)
	}

	if result.Type != lookup.AnswerTypeOutputList {
		return nil, errors.New("unexpected lookup result type")
	}

	parsedRecords := make([]*ProtocolDefinitionData, 0)
	for _, output := range result.Outputs {
		tx, err := transaction.NewTransactionFromBEEF(output.Beef)
		if err != nil {
			continue // Skip invalid transactions
		}
		lockingScript := tx.Outputs[output.OutputIndex].LockingScript
		record, err := parseLockingScript(DefinitionTypeProtocol, lockingScript)
		if err != nil {
			continue // Skip invalid records
		}
		if protocolRecord, ok := record.(*ProtocolDefinitionData); ok {
			parsedRecords = append(parsedRecords, protocolRecord)
		}
	}

	return parsedRecords, nil
}

// ResolveCertificate resolves certificate registry entries using a lookup service.
func (c *RegistryClient) ResolveCertificate(ctx context.Context, query CertificateQuery) ([]*CertificateDefinitionData, error) {
	resolver := c.lookupFactory()
	serviceName := mapDefinitionTypeToServiceName(DefinitionTypeCertificate)

	// Prepare the lookup query
	queryJSON, err := json.Marshal(query)
	if err != nil {
		return nil, fmt.Errorf("error marshalling query: %w", err)
	}

	// Make the lookup query
	result, err := resolver.Query(ctx, &lookup.LookupQuestion{
		Service: serviceName,
		Query:   queryJSON,
	})
	if err != nil {
		return nil, fmt.Errorf("lookup query error: %w", err)
	}

	if result.Type != lookup.AnswerTypeOutputList {
		return nil, errors.New("unexpected lookup result type")
	}

	parsedRecords := make([]*CertificateDefinitionData, 0)
	for _, output := range result.Outputs {
		tx, err := transaction.NewTransactionFromBEEF(output.Beef)
		if err != nil {
			continue // Skip invalid transactions
		}
		lockingScript := tx.Outputs[output.OutputIndex].LockingScript
		record, err := parseLockingScript(DefinitionTypeCertificate, lockingScript)
		if err != nil {
			continue // Skip invalid records
		}
		if certRecord, ok := record.(*CertificateDefinitionData); ok {
			parsedRecords = append(parsedRecords, certRecord)
		}
	}

	return parsedRecords, nil
}

// ListOwnRegistryEntries lists the registry operator's published definitions for the given type.
func (c *RegistryClient) ListOwnRegistryEntries(ctx context.Context, definitionType DefinitionType) ([]*RegistryRecord, error) {
	relevantBasketName := mapDefinitionTypeToBasketName(definitionType)

	includeInstructions := true
	includeTags := true
	includeLabels := true
	listResult, err := c.wallet.ListOutputs(ctx, wallet.ListOutputsArgs{
		Basket:                    relevantBasketName,
		Include:                   "entire transactions",
		IncludeCustomInstructions: &includeInstructions,
		IncludeTags:               &includeTags,
		IncludeLabels:             &includeLabels,
	}, c.originator)
	if err != nil {
		return nil, fmt.Errorf("failed to list outputs: %w", err)
	}

	// Add this for debugging tests
	if testLogger, ok := ctx.Value("testLogger").(interface{ Logf(string, ...interface{}) }); ok {
		testLogger.Logf("ListOwnRegistryEntries found %d outputs in basket %s", len(listResult.Outputs), relevantBasketName)
		testLogger.Logf("BEEF length: %d", len(listResult.BEEF))
		tx, txErr := transaction.NewTransactionFromBEEF(listResult.BEEF)
		if txErr != nil {
			testLogger.Logf("Error parsing BEEF: %v", txErr)
		} else {
			testLogger.Logf("Transaction has %d outputs", len(tx.Outputs))
			for i, output := range tx.Outputs {
				testLogger.Logf("Output %d: %d satoshis, script length: %d", i, output.Satoshis, len(output.LockingScript.Bytes()))
			}
		}
	}

	results := make([]*RegistryRecord, 0)
	for _, output := range listResult.Outputs {
		if !output.Spendable {
			continue
		}

		tx, err := transaction.NewTransactionFromBEEF(listResult.BEEF)
		if err != nil {
			continue // Skip invalid transaction
		}

		// Add this for debugging tests
		if testLogger, ok := ctx.Value("testLogger").(interface{ Logf(string, ...interface{}) }); ok {
			testLogger.Logf("Processing outpoint %s", output.Outpoint)
			testLogger.Logf("Transaction has %d outputs, output index: %d", len(tx.Outputs), output.Outpoint.Index)
			if int(output.Outpoint.Index) >= len(tx.Outputs) {
				testLogger.Logf("Output index %d is out of bounds", output.Outpoint.Index)
				continue
			}
		}

		lockingScript := tx.Outputs[output.Outpoint.Index].LockingScript
		recordData, err := parseLockingScript(definitionType, lockingScript)
		if err != nil {
			// Add this for debugging tests
			if testLogger, ok := ctx.Value("testLogger").(interface{ Logf(string, ...interface{}) }); ok {
				testLogger.Logf("Error parsing locking script: %v", err)
			}
			continue // Skip invalid records
		}

		// Create a registry record with both definition and token data
		record := &RegistryRecord{
			DefinitionData: recordData,
			TokenData: TokenData{
				TxID:          output.Outpoint.Txid.String(),
				OutputIndex:   output.Outpoint.Index,
				Satoshis:      output.Satoshis,
				LockingScript: lockingScript.String(),
				BEEF:          listResult.BEEF,
			},
		}

		results = append(results, record)
	}

	return results, nil
}

// RevokeOwnRegistryEntry revokes a registry record by spending its associated UTXO.
func (c *RegistryClient) RevokeOwnRegistryEntry(ctx context.Context, record *RegistryRecord) (*RevokeDefinitionResult, error) {
	if record.TxID == "" || record.LockingScript == "" {
		return nil, errors.New("invalid registry record - missing txid or lockingScript")
	}

	// Check if the registry record belongs to the current user
	currentIdentityKey, err := c.wallet.GetPublicKey(ctx, wallet.GetPublicKeyArgs{
		IdentityKey: true,
	}, c.originator)
	if err != nil {
		return nil, fmt.Errorf("failed to get identity public key: %w", err)
	}

	registryOperator := record.GetRegistryOperator()
	if registryOperator != currentIdentityKey.PublicKey.ToDERHex() {
		return nil, errors.New("this registry token does not belong to the current wallet")
	}

	// Create a descriptive label for the item we're revoking
	var itemIdentifier string
	switch data := record.DefinitionData.(type) {
	case *BasketDefinitionData:
		itemIdentifier = data.BasketID
	case *ProtocolDefinitionData:
		itemIdentifier = data.Name
	case *CertificateDefinitionData:
		if data.Name != "" {
			itemIdentifier = data.Name
		} else {
			itemIdentifier = data.Type
		}
	default:
		itemIdentifier = "unknown"
	}

	unlockScriptLength := uint32(73) // Estimated size for signature
	outpoint, err := wallet.OutpointFromString(fmt.Sprintf("%s.%d", record.TxID, record.OutputIndex))
	if err != nil {
		return nil, fmt.Errorf("failed to parse outpoint: %w", err)
	}

	// Create partial transaction that spends the registry UTXO
	createResult, err := c.wallet.CreateAction(ctx, wallet.CreateActionArgs{
		Description: fmt.Sprintf("Revoke %s item: %s", record.GetDefinitionType(), itemIdentifier),
		InputBEEF:   record.BEEF,
		Inputs: []wallet.CreateActionInput{
			{
				Outpoint:              *outpoint,
				UnlockingScriptLength: unlockScriptLength,
				InputDescription:      fmt.Sprintf("Revoking %s token", record.GetDefinitionType()),
			},
		},
	}, c.originator)
	if err != nil {
		return nil, fmt.Errorf("failed to create revocation transaction: %w", err)
	}

	if createResult.SignableTransaction == nil {
		return nil, errors.New("failed to create signable transaction")
	}

	partialTx, err := transaction.NewTransactionFromBEEF(createResult.SignableTransaction.Tx)
	if err != nil {
		return nil, fmt.Errorf("failed to parse partial transaction: %w", err)
	}

	// Prepare the unlocker
	pushDropTemplate := &pushdrop.PushDropTemplate{
		Wallet:     c.wallet,
		Originator: c.originator,
	}

	unlocker := pushDropTemplate.Unlock(
		ctx,
		mapDefinitionTypeToWalletProtocol(record.GetDefinitionType()),
		"1",
		wallet.Counterparty{
			Type: wallet.CounterpartyTypeAnyone,
		},
		wallet.SignOutputsAll,
		false,
	)

	// Apply signature to the unlocker
	finalUnlockScript, err := unlocker.Sign(partialTx, record.OutputIndex)
	if err != nil {
		return nil, fmt.Errorf("failed to sign transaction: %w", err)
	}

	// Complete signing with the final unlock script
	acceptDelayedBroadcast := false
	signResult, err := c.wallet.SignAction(ctx, wallet.SignActionArgs{
		Reference: createResult.SignableTransaction.Reference,
		Spends: map[uint32]wallet.SignActionSpend{
			record.OutputIndex: {
				UnlockingScript: finalUnlockScript.Bytes(),
			},
		},
		Options: &wallet.SignActionOptions{
			AcceptDelayedBroadcast: &acceptDelayedBroadcast,
		},
	}, c.originator)
	if err != nil {
		return nil, fmt.Errorf("failed to finalize the transaction signature: %w", err)
	}

	if signResult.Tx == nil {
		return nil, errors.New("failed to get signed transaction")
	}

	// Broadcast the revocation transaction
	var broadcaster transaction.Broadcaster
	if c.broadcasterFactory != nil {
		broadcaster, err = c.broadcasterFactory(
			[]string{mapDefinitionTypeToTopic(record.GetDefinitionType())},
			&topic.BroadcasterConfig{
				NetworkPreset: c.network,
			},
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create broadcaster using factory: %w", err)
		}
	} else {
		// Fallback to default creation method if no factory is set
		broadcasterImpl, err := topic.NewBroadcaster(
			[]string{mapDefinitionTypeToTopic(record.GetDefinitionType())},
			&topic.BroadcasterConfig{
				NetworkPreset: c.network,
			},
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create broadcaster: %w", err)
		}
		broadcaster = broadcasterImpl
	}

	signedTx, err := transaction.NewTransactionFromBEEF(signResult.Tx)
	if err != nil {
		return nil, fmt.Errorf("failed to create transaction from BEEF: %w", err)
	}

	success, failure := broadcaster.BroadcastCtx(ctx, signedTx)
	return &RevokeDefinitionResult{
		Success: success,
		Failure: failure,
	}, nil
}
