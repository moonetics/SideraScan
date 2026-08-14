package assets

import (
	_ "embed"

	"fyne.io/fyne/v2"
)

//go:embed siderascan-logo.png
var logo []byte

func Logo() fyne.Resource {
	return fyne.NewStaticResource("siderascan-logo.png", logo)
}
