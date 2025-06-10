// Package kvstore provides a key-value storage system backed by Bitcoin SV transactions.
// It enables persistent storage of data on-chain using transaction outputs, with support
// for encryption, basket-based organization, and configurable retention periods.
// The storage is wallet-integrated, allowing for authenticated operations and automatic
// management of transaction fees.
package kvstore

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/bsv-blockchain/go-sdk/v2/transaction"
	pushdroptpl "github.com/bsv-blockchain/go-sdk/v2/transaction/template/pushdrop"
	"github.com/bsv-blockchain/go-sdk/v2/wallet"
)

// LocalKVStore implements KVStoreInterface for local key-value storage
// using transaction outputs managed by a wallet.
type LocalKVStore struct {
	wallet     wallet.Interface
	context    string
	encrypt    bool
	originator string
	mu         sync.Mutex
}

// NewLocalKVStore creates a new LocalKVStore instance with the provided configuration.
func NewLocalKVStore(config KVStoreConfig) (*LocalKVStore, error) {
	if config.Wallet == nil {
		return nil, ErrInvalidWallet
	}
	if config.Context == "" {
		return nil, ErrEmptyContext
	}

	return &LocalKVStore{
		wallet:     config.Wallet,
		context:    config.Context,
		encrypt:    config.Encrypt,
		originator: config.Originator,
	}, nil
}

// getProtocol returns the wallet protocol for the given key
func (kv *LocalKVStore) getProtocol(key string) wallet.Protocol {
	// SecurityLevelEveryAppAndCounterparty seems appropriate for a shared KV store concept
	return wallet.Protocol{
		SecurityLevel: wallet.SecurityLevelEveryAppAndCounterparty,
		Protocol:      kv.context,
	}
}

// lookupValueResult holds the result of a key lookup operation
type lookupValueResult struct {
	value       string
	outpoints   []transaction.Outpoint
	inputBeef   []byte // The raw BEEF data containing all inputs for spending
	lor         *wallet.ListOutputsResult
	valueExists bool
}

// lookupValue finds the current value for a key
func (kv *LocalKVStore) lookupValue(ctx context.Context, key string, defaultValue string, limit int) (*lookupValueResult, error) {
	outputsResult, err := kv.getOutputs(ctx, key, limit)
	if err != nil {
		// Wrap wallet operation error
		return nil, fmt.Errorf("error ListOutputs: %w", err)
	}

	if len(outputsResult.Outputs) == 0 {
		return &lookupValueResult{
			value:       defaultValue,
			outpoints:   []transaction.Outpoint{},
			lor:         outputsResult,
			valueExists: false,
		}, nil
	}

	// Match TS: Use the *last* output returned by ListOutputs.
	// This implicitly assumes the wallet returns outputs in a meaningful order (ideally chronologically ascending).
	mostRecentOutput := outputsResult.Outputs[len(outputsResult.Outputs)-1]

	// We need the BEEF data to extract the transaction
	if len(outputsResult.BEEF) == 0 {
		// This indicates an issue with ListOutputs or the data state
		return nil, fmt.Errorf("error BEEF")
	}

	// Use NewBeefFromAtomicBytes to handle the potential ATOMIC_BEEF prefix
	beefData, subjectTxidHash, err := transaction.NewBeefFromAtomicBytes(outputsResult.BEEF)
	if err != nil {
		// Fallback or further check? The error might be invalid version OR invalid BEEF structure.
		// If NewBeefFromAtomicBytes fails, it implies it's not atomic or the internal beef is bad.
		// Let's try parsing as standard BEEF V1/V2 just in case, though wallet should provide atomic.
		beefData, err = transaction.NewBeefFromBytes(outputsResult.BEEF)
		if err != nil {
			return nil, fmt.Errorf("error BEEF/AtomicBEEF: %w", err)
		}
		// If standard parsing worked, we don't have a subject TXID from the prefix
		subjectTxidHash = nil
	}

	// Extract txid and vout from outpoint string of the *most recent output*
	txidStr := mostRecentOutput.Outpoint.Txid.String()
	vout := mostRecentOutput.Outpoint.Index

	// Find the transaction corresponding to the most recent output's txid within the BEEF data
	tx := beefData.FindTransaction(txidStr)
	if tx == nil {
		// It's possible the subject TXID from AtomicBEEF prefix *is* the one we want, if ListOutputs only returned one output's BEEF
		if subjectTxidHash != nil && subjectTxidHash.String() == txidStr {
			tx = beefData.FindAtomicTransaction(subjectTxidHash.String()) // Re-find using the atomic method which links inputs
		}
		if tx == nil {
			return nil, fmt.Errorf("error BEEF transaction %s not found in BEEF data", txidStr)
		}
	}

	// Check if vout is valid for the transaction
	if int(vout) >= len(tx.Outputs) {
		return nil, fmt.Errorf("error Transaction vout %d out of range for tx %s with %d outputs", vout, txidStr, len(tx.Outputs))
	}
	txOutput := tx.Outputs[vout]
	if txOutput == nil || txOutput.LockingScript == nil {
		return nil, fmt.Errorf("invalid output or locking script at index %d in transaction %s", vout, txidStr)
	}

	// Extract push drop data from script object (which is already parsed)
	pushDropData := pushdroptpl.Decode(txOutput.LockingScript)
	if pushDropData == nil || len(pushDropData.Fields) < 1 {
		return nil, fmt.Errorf("invalid pushdrop token format found for key %s in output %s", key, mostRecentOutput.Outpoint)
	}

	valueBytes := pushDropData.Fields[0]
	value := string(valueBytes) // Assuming UTF8 for now

	// Decrypt value if encryption is enabled
	if kv.encrypt {
		protocol := kv.getProtocol(key)
		decryptArgs := wallet.DecryptArgs{
			EncryptionArgs: wallet.EncryptionArgs{
				ProtocolID:   protocol,
				KeyID:        key,
				Counterparty: wallet.Counterparty{Type: wallet.CounterpartyTypeSelf}, // Assuming self-encryption
			},
			Ciphertext: valueBytes,
		}
		decryptResult, err := kv.wallet.Decrypt(ctx, decryptArgs, kv.originator)
		if err != nil {
			// Wrap encryption error
			return nil, fmt.Errorf("for key %s: %w", key, err)
		}
		value = string(decryptResult.Plaintext)
	}

	// Collect all outpoints for the key
	outpoints := make([]transaction.Outpoint, len(outputsResult.Outputs))
	for i, output := range outputsResult.Outputs {
		outpoints[i] = output.Outpoint
	}

	return &lookupValueResult{
		value:       value,
		outpoints:   outpoints,
		inputBeef:   outputsResult.BEEF, // Return the original BEEF received
		lor:         outputsResult,
		valueExists: true,
	}, nil
}

// getOutputs lists all outputs with the specified key in the context
func (kv *LocalKVStore) getOutputs(ctx context.Context, key string, limit int) (*wallet.ListOutputsResult, error) {
	// List outputs matching the basket and key tag
	listArgs := wallet.ListOutputsArgs{
		Basket:  kv.context,
		Tags:    []string{key},
		Include: "entire transactions",
		Limit:   uint32(limit),
	}
	result, err := kv.wallet.ListOutputs(ctx, listArgs, kv.originator)
	if err != nil {
		// Return wrapped wallet error
		return nil, fmt.Errorf("error ListOutputs for key %s: %w", key, err)
	}
	return result, nil
}

// Get retrieves a value for the given key, or returns the defaultValue if not found.
func (kv *LocalKVStore) Get(ctx context.Context, key string, defaultValue string) (string, error) {
	if key == "" {
		return "", ErrInvalidKey
	}
	result, err := kv.lookupValue(ctx, key, defaultValue, 5)
	if err != nil {
		// If lookup failed, return the error directly.
		// The lookupValue function is responsible for wrapping specific errors.
		// The caller can use errors.Is or errors.As to check the type.
		return defaultValue, err
	}

	// If lookupValue succeeded but value doesn't exist (e.g., empty outputs),
	// return the default value without error.
	if !result.valueExists {
		// Here, we could potentially return kvstore.ErrKeyNotFound if defaultValue was empty
		// to distinguish between an empty stored value and a non-existent key.
		// For now, matching TS behavior: return default, no error.
		return defaultValue, nil
	}

	return result.value, nil
}

// Set stores a value with the given key, returning the outpoint of the transaction output.
func (kv *LocalKVStore) Set(ctx context.Context, key string, value string) (string, error) {
	if key == "" {
		return "", ErrInvalidKey
	}
	if value == "" {
		return "", ErrInvalidValue
	}

	// Lock to prevent concurrent access
	kv.mu.Lock()
	defer kv.mu.Unlock()
	lookupResult, err := kv.lookupValue(ctx, key, "", 10)
	// Handle specific errors from lookup
	if err != nil && !errors.Is(err, ErrKeyNotFound) { // Proceed if key simply not found, otherwise log/handle error
		if errors.Is(err, ErrCorruptedState) {
			// Don't proceed if the state is known to be corrupted?
			return "", fmt.Errorf("cannot set key %s due to existing corrupted state: %w", key, err)
		}
		// Log other lookup errors but attempt to proceed with Set (overwrite)
		fmt.Printf("Warning: lookupValue failed during Set for key %s: %v\n", key, err)
		lookupResult = &lookupValueResult{valueExists: false, outpoints: []transaction.Outpoint{}, lor: &wallet.ListOutputsResult{}}
	} else if err == nil && !lookupResult.valueExists { // Handle case where getOutputs was empty
		lookupResult = &lookupValueResult{valueExists: false, outpoints: []transaction.Outpoint{}, lor: &wallet.ListOutputsResult{}}
	}

	if lookupResult.valueExists && lookupResult.value == value && len(lookupResult.outpoints) > 0 {
		return lookupResult.outpoints[0].String(), nil
	}

	valueBytes := []byte(value)
	if kv.encrypt {
		protocol := kv.getProtocol(key)
		encryptArgs := wallet.EncryptArgs{
			EncryptionArgs: wallet.EncryptionArgs{
				ProtocolID:   protocol,
				KeyID:        key,
				Counterparty: wallet.Counterparty{Type: wallet.CounterpartyTypeSelf},
			},
			Plaintext: valueBytes,
		}
		encryptResult, err := kv.wallet.Encrypt(ctx, encryptArgs, kv.originator)
		if err != nil {
			return "", fmt.Errorf("for key %s: %w", key, err)
		}
		valueBytes = encryptResult.Ciphertext
	}

	pushDrop := pushdroptpl.PushDropTemplate{Wallet: kv.wallet, Originator: kv.originator}
	lockingScript, err := pushDrop.Lock(
		ctx,
		[][]byte{valueBytes},
		kv.getProtocol(key),
		key,
		wallet.Counterparty{Type: wallet.CounterpartyTypeSelf},
		true,
		false,
		true,
	)
	if err != nil {
		// Error creating script itself, not a wallet op yet
		return "", fmt.Errorf("failed to create PushDrop locking script: %w", err)
	}

	inputs := make([]wallet.CreateActionInput, 0, len(lookupResult.outpoints))
	for _, outpoint := range lookupResult.outpoints {
		unlocker := pushDrop.Unlock(
			ctx,
			kv.getProtocol(key),
			key,
			wallet.Counterparty{Type: wallet.CounterpartyTypeSelf},
			wallet.SignOutputsAll,
			false,
		)
		inputs = append(inputs, wallet.CreateActionInput{
			Outpoint:              outpoint,
			InputDescription:      "Previous key-value token",
			UnlockingScriptLength: unlocker.EstimateLength(),
		})
	}

	createArgs := wallet.CreateActionArgs{
		Description: fmt.Sprintf("Update %s in %s", key, kv.context),
		InputBEEF:   lookupResult.inputBeef,
		Inputs:      inputs,
		Outputs: []wallet.CreateActionOutput{
			{
				LockingScript:     lockingScript.Bytes(),
				Satoshis:          1,
				OutputDescription: "Key-value token",
				Basket:            kv.context,
				Tags:              []string{key},
			},
		},
		Options: &wallet.CreateActionOptions{
			// RandomizeOutputs: false, // Default is usually false?
		},
	}

	createResult, err := kv.wallet.CreateAction(ctx, createArgs, kv.originator)
	if err != nil {
		// Wrap wallet create action error
		return "", fmt.Errorf("error CreateAction: %w", err)
	}

	if len(inputs) == 0 {
		if createResult.Txid == [32]byte{} {
			return "", errors.New("CreateAction returned no txid and no signable transaction for new key")
		}
		return fmt.Sprintf("%s.0", createResult.Txid.String()), nil
	}

	if createResult.SignableTransaction == nil {
		return "", errors.New("CreateAction did not return a signable transaction when inputs were provided")
	}

	spends, err := kv.prepareSpends(ctx, key, inputs, createResult.SignableTransaction.Tx, createArgs.InputBEEF)
	if err != nil {
		// Error occurred during signing preparation (e.g., decoding tx, generating unlock script)
		return "", fmt.Errorf("failed to prepare spends for signing: %w", err)
	}

	signArgs := wallet.SignActionArgs{
		Reference: createResult.SignableTransaction.Reference,
		Spends:    spends,
	}

	signResult, err := kv.wallet.SignAction(ctx, signArgs, kv.originator)
	if err != nil {
		// *** Add Relinquish logic here ***
		fmt.Printf("Warning: SignAction failed for Set key %s. Attempting to relinquish inputs. Error: %v\n", key, err)
		for _, input := range inputs {
			relinquishArgs := wallet.RelinquishOutputArgs{
				Basket: kv.context,
				Output: input.Outpoint,
			}
			_, relinquishErr := kv.wallet.RelinquishOutput(ctx, relinquishArgs, kv.originator)
			if relinquishErr != nil {
				fmt.Printf("Warning: Failed to relinquish output %s for key %s after SignAction failure: %v\n", input.Outpoint, key, relinquishErr)
			}
		}
		// Return the original wrapped signing error
		return "", fmt.Errorf("error SignAction: %w", err)
	}

	return fmt.Sprintf("%s.0", signResult.Txid), nil
}

// prepareSpends generates the signing instructions for the inputs of a transaction.
func (kv *LocalKVStore) prepareSpends(ctx context.Context, key string, inputs []wallet.CreateActionInput, signableTxBytes []byte, inputBeef []byte) (map[uint32]wallet.SignActionSpend, error) {
	spends := make(map[uint32]wallet.SignActionSpend)

	// Parse the input BEEF first to provide context for linking
	beefData, err := transaction.NewBeefFromBytes(inputBeef)
	if err != nil {
		// Attempt atomic parse as fallback, though merged beef likely isn't atomic
		beefDataAtomic, _, errAtomic := transaction.NewBeefFromAtomicBytes(inputBeef)
		if errAtomic != nil {
			return nil, fmt.Errorf("err InputBeef failed to decode input BEEF as standard or atomic: %w / %w", err, errAtomic)
		}
		beefData = beefDataAtomic // Use atomic if standard failed
	}

	// Parse the signable transaction bytes just to get its TxID
	tempTx, err := transaction.NewTransactionFromBytes(signableTxBytes)
	if err != nil {
		return nil, fmt.Errorf("error SignableTransactionBytes failed to decode signable tx bytes: %w", err)
	}

	// Use FindTransactionForSigning with the parsed BEEF to get a TX with linked inputs
	signableTx := beefData.FindTransactionForSigning(tempTx.TxID().String())
	if signableTx == nil {
		return nil, fmt.Errorf("error SignableTransactionInBeef signable tx %s not found within provided InputBEEF context", tempTx.TxID())
	}

	// Now signableTx.Inputs[i].SourceTransaction should be populated
	pushDrop := pushdroptpl.PushDropTemplate{Wallet: kv.wallet, Originator: kv.originator}

	for i := range inputs {
		// Check if SourceTransaction was linked
		if i >= len(signableTx.Inputs) || signableTx.Inputs[i].SourceTransaction == nil {
			// This check might be redundant if FindTransactionForSigning guarantees linking or errors out, but good for safety
			return nil, fmt.Errorf("failed to link source transaction for input %d (txid: %s) using provided InputBEEF", i, inputs[i].Outpoint)
		}

		unlocker := pushDrop.Unlock(
			ctx,
			kv.getProtocol(key),
			key,
			wallet.Counterparty{Type: wallet.CounterpartyTypeSelf},
			wallet.SignOutputsAll,
			false,
		)
		unlockingScript, err := unlocker.Sign(signableTx, uint32(i))
		if err != nil {
			// Signing error for a specific input
			return nil, fmt.Errorf("failed to sign input %d: %w", i, err) // Consider wrapping as ErrTransactionSign?
		}
		spends[uint32(i)] = wallet.SignActionSpend{
			UnlockingScript: unlockingScript.Bytes(),
		}
	}
	return spends, nil
}

// Remove deletes all values for the given key by spending the outputs.
func (kv *LocalKVStore) Remove(ctx context.Context, key string) ([]string, error) {
	if key == "" {
		return nil, ErrInvalidKey
	}
	removedTxids := []string{}

	for {
		lookupResult, err := kv.lookupValue(ctx, key, "", 100)
		if err != nil {
			if errors.Is(err, ErrKeyNotFound) { // If lookup confirms no key, we are done
				break
			}
			// If lookup fails for other reasons, return partial results and error
			return removedTxids, fmt.Errorf("error looking up outputs to remove for key %s: %w", key, err)
		}

		if !lookupResult.valueExists || len(lookupResult.outpoints) == 0 {
			break
		}

		pushDrop := pushdroptpl.PushDropTemplate{Wallet: kv.wallet, Originator: kv.originator}
		inputs := make([]wallet.CreateActionInput, 0, len(lookupResult.outpoints))
		for _, outpoint := range lookupResult.outpoints {
			unlocker := pushDrop.Unlock(
				ctx,
				kv.getProtocol(key),
				key,
				wallet.Counterparty{Type: wallet.CounterpartyTypeSelf},
				wallet.SignOutputsAll,
				false,
			)
			inputs = append(inputs, wallet.CreateActionInput{
				Outpoint:              outpoint,
				InputDescription:      "Removing key-value token",
				UnlockingScriptLength: unlocker.EstimateLength(),
			})
		}

		createArgs := wallet.CreateActionArgs{
			Description: fmt.Sprintf("Remove %s from %s", key, kv.context),
			InputBEEF:   lookupResult.inputBeef,
			Inputs:      inputs,
			Outputs:     []wallet.CreateActionOutput{},
			Options:     &wallet.CreateActionOptions{},
		}
		createResult, err := kv.wallet.CreateAction(ctx, createArgs, kv.originator)
		if err != nil {
			// *** Add Relinquish logic here? ***
			// Should we relinquish if CreateAction fails? The TS reference might only do it on SignAction fail.
			// Let's only add it to SignAction failure for now, mirroring the Set logic.
			return removedTxids, errors.New(fmt.Sprintln("CreateAction (Remove)", err))
		}

		if createResult.SignableTransaction == nil {
			return removedTxids, errors.New("createAction did not return signable tx for removal")
		}

		spends, err := kv.prepareSpends(ctx, key, inputs, createResult.SignableTransaction.Tx, createArgs.InputBEEF)
		if err != nil {
			return removedTxids, fmt.Errorf("failed to prepare spends for removal signing: %w", err)
		}

		signArgs := wallet.SignActionArgs{
			Reference: createResult.SignableTransaction.Reference,
			Spends:    spends,
		}
		signResult, err := kv.wallet.SignAction(ctx, signArgs, kv.originator)
		if err != nil {
			// *** Add Relinquish logic here ***
			fmt.Printf("Warning: SignAction failed for Remove key %s. Attempting to relinquish inputs. Error: %v\n", key, err)
			for _, input := range inputs {
				relinquishArgs := wallet.RelinquishOutputArgs{
					Basket: kv.context,
					Output: input.Outpoint,
				}
				_, relinquishErr := kv.wallet.RelinquishOutput(ctx, relinquishArgs, kv.originator)
				if relinquishErr != nil {
					fmt.Printf("Warning: Failed to relinquish output %s for key %s after SignAction failure: %v\n", input.Outpoint, key, relinquishErr)
				}
			}
			// Return the original wrapped signing error
			return removedTxids, fmt.Errorf("SignAction (Remove): %w", err)
		}

		removedTxids = append(removedTxids, signResult.Txid.String())

		if len(lookupResult.outpoints) < 100 {
			break
		}
	}

	return removedTxids, nil
}
