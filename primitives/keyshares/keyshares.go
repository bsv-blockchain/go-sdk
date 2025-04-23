package primitives

import (
	"fmt"
	"strconv"
	"strings"
)

type KeyShares struct {
	Points    []*PointInFiniteField
	Threshold int
	Integrity string
}

// decodeShare decodes the share from the backup format
func decodeShare(share string) (*PointInFiniteField, int, string, error) {
	components := strings.Split(share, ".")
	if len(components) != 4 {
		err := fmt.Errorf("invalid share format. Expected format: \"x.y.t.i\" - received %s", share)
		return nil, 0, "", err
	}

	point, err := PointFromString(components[0] + "." + components[1])
	if err != nil {
		return nil, 0, "", err
	}

	t := components[2]
	if t == "" {
		return nil, 0, "", fmt.Errorf("threshold not found")
	}
	i := components[3]
	if i == "" {
		return nil, 0, "", fmt.Errorf("integrity not found")
	}
	tInt, err := strconv.Atoi(t)
	if err != nil {
		return nil, 0, "", err
	}
	return point, tInt, i, nil
}

// NewKeySharesFromBackupFormat creates a new KeyShares object from a backup
func NewKeySharesFromBackupFormat(shares []string) (keyShares *KeyShares, error error) {
	var threshold = 0
	var integrity = ""
	points := make([]*PointInFiniteField, 0)
	for idx, share := range shares {
		point, tInt, i, err := decodeShare(share)
		if err != nil {
			return nil, fmt.Errorf("failed to decode share %d: %w", idx, err)
		}

		if idx != 0 && threshold != tInt {
			return nil, fmt.Errorf("threshold mismatch in share %d", idx)
		}
		if idx != 0 && integrity != i {
			return nil, fmt.Errorf("integrity mismatch in share %d", idx)
		}
		threshold = tInt
		integrity = i
		points = append(points, point)
	}
	return NewKeyShares(points, threshold, integrity), nil
}

/**
 * @method ToBackupFormat
 *
 * Creates a backup of the keyshares
 *
 * @returns shares in backup format
 */
func (k *KeyShares) ToBackupFormat() ([]string, error) {
	backupShares := make([]string, 0)
	for _, share := range k.Points {
		backupShares = append(backupShares, share.String()+"."+strconv.Itoa(k.Threshold)+"."+k.Integrity)
	}
	return backupShares, nil
}

func NewKeyShares(points []*PointInFiniteField, threshold int, integrity string) *KeyShares {
	return &KeyShares{
		Points:    points,
		Threshold: threshold,
		Integrity: integrity,
	}
}
