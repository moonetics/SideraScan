//go:build windows

package crypto

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

type DPAPIProtector struct{}

func NewProtector() Protector {
	return DPAPIProtector{}
}

func (DPAPIProtector) Protect(input []byte) ([]byte, error) {
	return cryptProtect(input)
}

func (DPAPIProtector) Unprotect(input []byte) ([]byte, error) {
	return cryptUnprotect(input)
}

func cryptProtect(input []byte) ([]byte, error) {
	dataIn := bytesToBlob(input)
	var dataOut windows.DataBlob

	err := windows.CryptProtectData(dataIn, nil, nil, 0, nil, 0, &dataOut)
	if err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(dataOut.Data)))

	return blobToBytes(&dataOut), nil
}

func cryptUnprotect(input []byte) ([]byte, error) {
	dataIn := bytesToBlob(input)
	var dataOut windows.DataBlob

	err := windows.CryptUnprotectData(dataIn, nil, nil, 0, nil, 0, &dataOut)
	if err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(dataOut.Data)))

	return blobToBytes(&dataOut), nil
}

func bytesToBlob(input []byte) *windows.DataBlob {
	if len(input) == 0 {
		return &windows.DataBlob{}
	}

	return &windows.DataBlob{
		Size: uint32(len(input)),
		Data: &input[0],
	}
}

func blobToBytes(blob *windows.DataBlob) []byte {
	if blob == nil || blob.Data == nil || blob.Size == 0 {
		return []byte{}
	}

	bytes := unsafe.Slice(blob.Data, blob.Size)
	return append([]byte(nil), bytes...)
}
