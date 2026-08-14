package payload

import (
	"bytes"
	"encoding/json"

	"github.com/moonetics/SideraScan/apps/scanner/internal/contract"
)

var jsonNullEscape = []byte(`\u0000`)

func SanitizeForUpload(request contract.UploadResultsRequest) (contract.UploadResultsRequest, error) {
	encoded, err := json.Marshal(request)
	if err != nil {
		return contract.UploadResultsRequest{}, err
	}

	encoded = bytes.ReplaceAll(encoded, jsonNullEscape, nil)

	var clean contract.UploadResultsRequest
	if err := json.Unmarshal(encoded, &clean); err != nil {
		return contract.UploadResultsRequest{}, err
	}

	return clean, nil
}
