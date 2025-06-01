# Custom Fee Modeling Example

This example demonstrates how to implement a custom fee model by creating a struct that satisfies the `transaction.FeeModel` interface. This allows for flexible and application-specific fee calculation logic beyond standard satoshis-per-kilobyte.

## Overview

The `fee_modeling` example (using `fee_modeling.go`) showcases:
1. Defining a struct `Example` with a `Value` (which could represent a base fee rate or factor).
2. Implementing the `ComputeFee(tx transaction.Transaction) uint64` method for this struct.
3. Inside `ComputeFee`:
    - A special rule: if `tx.Version == 3301`, the fee is 0.
    - Calculating the transaction size by iterating through inputs and outputs and summing their components (txid, index, sequence, script lengths, scripts, satoshi amounts, lock time, etc.).
    - Calculating an initial fee based on the size and the `Example` struct's `Value` (e.g., `(size / 1000) * e.Value`).
    - Applying custom rules:
        - An "inputs incentive": if the number of inputs is at least three times the number of outputs, the fee is reduced by 20%.
        - An "outputs penalty": if the number of outputs is at least one-fifth the number of inputs, the fee is increased by 10%.
    - Using `math.Ceil` to round the fee up to the nearest satoshi.

## Code Walkthrough

### Custom Fee Model Implementation

```go
type Example struct {
    Value int // Example: base rate for fee calculation
}

func (e *Example) ComputeFee(tx transaction.Transaction) uint64 {
    // Special condition for version 3301 transactions
    if tx.Version == 3301 {
        return 0
    }

    // Calculate transaction size
    size := 4 // version
    size += util.VarInt(uint64(len(tx.Inputs))).Length() // number of inputs
    for _, input := range tx.Inputs {
        size += 40 // txid, output index, sequence number
        var scriptLength int
        if input.UnlockingScript != nil {
            scriptLength = len(*input.UnlockingScript)
        } else {
            // For accurate size estimation, unlocking scripts (or templates
            // that can provide an estimated size) are needed.
            panic("All inputs must have an unlocking script or an unlocking script template for sat/kb fee computation.")
        }
        size += util.VarInt(scriptLength).Length() // unlocking script length
        size += scriptLength                       // unlocking script
    }
    // ... (similar calculation for outputs) ...
    size += 4 // lock time

    // Initial fee calculation (e.g., based on satoshis per kilobyte)
    fee := float64((size / 1000) * e.Value) // e.Value could be sats/kB

    // Apply custom incentive/penalty rules
    if uint64(len(tx.Inputs))/3 >= uint64(len(tx.Outputs)) { // Input incentive
        fee *= 0.8
    }
    if uint64(len(tx.Outputs))/5 >= uint64(len(tx.Inputs)) { // Output penalty
        fee *= 1.1
    }

    // Round up to the nearest satoshi
    return uint64(math.Ceil(fee))
}
```
The `ComputeFee` method first estimates the transaction's byte size. It then calculates a base fee, potentially using `e.Value` as a rate (e.g., satoshis per kilobyte). Finally, it applies specific business logic: rewarding transactions with a higher input-to-output ratio and penalizing those with a relatively high number of outputs compared to inputs.

## How to Use

To use this custom fee model with a transaction:
1. Create an instance of your custom fee model struct:
   ```go
   myFeeModel := &Example{Value: 50} // Example: 50 satoshis per 1000 bytes base rate
   ```
2. When building a transaction and you need to calculate fees (e.g., for a change output or to ensure sufficient fees), you can assign it to the transaction object if the SDK supports setting a custom fee model directly, or call its `ComputeFee` method.
   ```go
   // If the transaction object has a way to set a fee model:
   // tx.SetFeeModel(myFeeModel)
   // totalFee := tx.CalculateFee() // Assuming a method that uses the set model

   // Or, call it directly:
   // estimatedFee := myFeeModel.ComputeFee(yourTransactionObject)
   ```
   The BSV Go SDK's `Transaction` object typically uses its `FeePerKB` field with standard fee calculation. To integrate a fully custom model like this for automatic change calculation or signing, you might need to:
    a. Calculate the fee manually using `myFeeModel.ComputeFee(tx)`.
    b. Manually adjust outputs or ensure inputs cover this fee plus output amounts.
    c. When signing (if the signing process itself doesn't rely on a pre-set `FeePerKB` for estimations), ensure the transaction is correctly balanced.

   The primary use of implementing `transaction.FeeModel` would be if the SDK's transaction processing pipeline (e.g., during `tx.Sign()` or change calculation) internally calls the `ComputeFee` method of an assigned model. If not, this serves as a standalone calculator. The example code itself only provides the `ComputeFee` method and doesn't show it being integrated into a `Transaction` object's lifecycle directly.

**Note**:
- The size calculation in this example assumes that `UnlockingScript` is populated for all inputs. If inputs use `UnlockingScriptTemplate`, the template would need to provide an estimated size for accurate fee calculation prior to final signing.
- This custom model provides an alternative to the simpler, flat satoshi-per-kilobyte models (like those in `transaction/fees.go`).

## Integration Steps

To use a custom fee model in your application:
1. Define a struct (e.g., `MyCustomFeeModel`).
2. Implement the `ComputeFee(tx transaction.Transaction) uint64` method for this struct, containing your specific fee logic.
3. When constructing transactions:
    - Create an instance of your custom fee model.
    - Calculate the required fee using `yourFeeModel.ComputeFee(yourTx)`.
    - Ensure your transaction's inputs and outputs are balanced to cover this fee. For instance, when adding a change output, subtract this computed fee from the total change amount.
    - The SDK's `tx.Sign()` might internally re-calculate fees if `tx.FeePerKB` is set. If you are using a fully custom model, ensure this interaction is understood. You might need to calculate the fee, set outputs (including change) explicitly, and then sign a transaction that is already "fee-paid" according to your model.

## Additional Resources

For more information, see:
- [Package Documentation - Transaction](https://pkg.go.dev/github.com/bsv-blockchain/go-sdk/transaction)
- [Standard Fee Models in SDK (transaction/fees.go)](https://github.com/bsv-blockchain/go-sdk/blob/master/transaction/fees.go) (for comparison)
