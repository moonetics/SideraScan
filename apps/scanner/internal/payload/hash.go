package payload

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/moonetics/SideraScan/apps/scanner/internal/contract"
)

func HashUploadPayload(input contract.UploadResultsRequest) (string, error) {
	clean := input
	clean.UploadToken = ""
	clean.Nonce = ""

	bytes, err := json.Marshal(clean)
	if err != nil {
		return "", fmt.Errorf("marshal payload for hash: %w", err)
	}

	sum := sha256.Sum256(bytes)
	return hex.EncodeToString(sum[:]), nil
}
