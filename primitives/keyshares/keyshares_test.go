package primitives

import (
	"encoding/hex"
	"math/big"
	"testing"

	base58 "github.com/bsv-blockchain/go-sdk/v2/compat/base58"
)

func TestNewKeyshares(t *testing.T) {
	points := []*PointInFiniteField{
		NewPointInFiniteField(big.NewInt(0), big.NewInt(1)),
		NewPointInFiniteField(big.NewInt(1), big.NewInt(2)),
		NewPointInFiniteField(big.NewInt(2), big.NewInt(3)),
	}
	threshold := 3
	integrity := hex.EncodeToString([]byte("integrity"))
	keyShares := NewKeyShares(points, threshold, integrity)
	if keyShares == nil {
		t.Errorf("Failed to create new key shares")
	}

	// test backup format
	backup, err := keyShares.ToBackupFormat()
	if err != nil {
		t.Errorf("Failed to convert key shares to backup format: %v", err)
	}
	if len(backup) != 3 {
		t.Errorf("Expected 3 shares, got %d", len(backup))
	}

	newShares, err := NewKeySharesFromBackupFormat(backup)
	if err != nil {
		t.Errorf("Failed to create key shares from backup format: %v", err)
	}

	if keyShares == nil {
		t.Errorf("Failed to create new key shares")
		return
	}

	if newShares.Threshold != keyShares.Threshold {
		t.Errorf("Threshold mismatch. Expected %d, got %d", keyShares.Threshold, newShares.Threshold)
	}
}

func TestInvalidBackupFormat(t *testing.T) {
	_, err := NewKeySharesFromBackupFormat([]string{"invalid"})
	if err == nil {
		t.Errorf("Expected error for invalid backup format")
	}

	// test invalid x value
	invalidX := "aGVsbG81281281281282="
	// base58 encoded "hello"
	validX := base58.Encode([]byte("hello"))
	invalidY := "d29ybGQ1231231231232="
	validY := base58.Encode([]byte("world"))
	integrity := hex.EncodeToString([]byte("integrity"))
	invalidShare := invalidX + "." + validY + ".3." + integrity
	_, err = NewKeySharesFromBackupFormat([]string{invalidShare})
	if err == nil {
		t.Errorf("Expected error for invalid x value")
	}

	invalidShare2 := validX + "." + invalidY + ".3." + integrity
	_, err = NewKeySharesFromBackupFormat([]string{invalidShare2})
	if err == nil {
		t.Errorf("Expected error for invalid y value")
	}

	// test invalid threshold
	invalidShare3 := validX + "." + validY + ".invalid." + integrity
	_, err = NewKeySharesFromBackupFormat([]string{invalidShare3})
	if err == nil {
		t.Errorf("Expected error for invalid threshold")
	}

	// test missing threshold
	invalidShare4 := validX + "." + validY + ".." + integrity
	_, err = NewKeySharesFromBackupFormat([]string{invalidShare4})
	if err == nil {
		t.Errorf("Expected error for missing threshold")
	}

	// test missing integrity
	invalidShare5 := validX + "." + validY + ".3."
	_, err = NewKeySharesFromBackupFormat([]string{invalidShare5})
	if err == nil {
		t.Errorf("Expected error for missing integrity")
	}

	// test mismatch threshold in shares
	invalidShare6 := validX + "." + validY + ".3." + integrity
	invalidShare7 := validX + "." + validY + ".4." + integrity
	_, err = NewKeySharesFromBackupFormat([]string{invalidShare6, invalidShare7})
	if err == nil {
		t.Errorf("Expected error for mismatch threshold")
	}

	// test mismatch integrity in shares
	invalidShare8 := validX + "." + validY + ".3." + integrity
	invalidShare9 := validX + "." + validY + ".3." + integrity + "1"
	_, err = NewKeySharesFromBackupFormat([]string{invalidShare8, invalidShare9})
	if err == nil {
		t.Errorf("Expected error for mismatch integrity")
	}
}
