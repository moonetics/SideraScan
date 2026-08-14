package ui

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

var (
	colorBackground   = color.NRGBA{R: 0x0f, G: 0x17, B: 0x2a, A: 0xff}
	colorPanel        = color.NRGBA{R: 0x16, G: 0x25, B: 0x44, A: 0xff}
	colorPanelSoft    = color.NRGBA{R: 0x1f, G: 0x33, B: 0x5d, A: 0xff}
	colorAccent       = color.NRGBA{R: 0x21, G: 0xa7, B: 0xc5, A: 0xff}
	colorAccentStrong = color.NRGBA{R: 0x2d, G: 0xd4, B: 0xbf, A: 0xff}
	colorForeground   = color.NRGBA{R: 0xe5, G: 0xee, B: 0xfb, A: 0xff}
	colorMuted        = color.NRGBA{R: 0x8a, G: 0xa0, B: 0xc2, A: 0xff}
	colorBorder       = color.NRGBA{R: 0x94, G: 0xa3, B: 0xb8, A: 0x38}
)

type sideraTheme struct{}

func NewTheme() fyne.Theme {
	return sideraTheme{}
}

func (sideraTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNameBackground:
		return colorBackground
	case theme.ColorNameForeground:
		return colorForeground
	case theme.ColorNamePrimary:
		return colorAccent
	case theme.ColorNameButton:
		return colorPanelSoft
	case theme.ColorNameInputBackground:
		return color.NRGBA{R: 0x09, G: 0x12, B: 0x24, A: 0xff}
	case theme.ColorNamePlaceHolder:
		return colorMuted
	case theme.ColorNameDisabled:
		return color.NRGBA{R: 0x62, G: 0x75, B: 0x94, A: 0xff}
	case theme.ColorNameDisabledButton:
		return color.NRGBA{R: 0x1b, G: 0x29, B: 0x42, A: 0xff}
	case theme.ColorNameHover:
		return color.NRGBA{R: 0x21, G: 0xa7, B: 0xc5, A: 0x24}
	case theme.ColorNamePressed:
		return color.NRGBA{R: 0x2d, G: 0xd4, B: 0xbf, A: 0x33}
	case theme.ColorNameSelection:
		return color.NRGBA{R: 0x21, G: 0xa7, B: 0xc5, A: 0x45}
	case theme.ColorNameSeparator:
		return colorBorder
	default:
		return theme.DefaultTheme().Color(name, variant)
	}
}

func (sideraTheme) Font(style fyne.TextStyle) fyne.Resource {
	return theme.DefaultTheme().Font(style)
}

func (sideraTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}

func (sideraTheme) Size(name fyne.ThemeSizeName) float32 {
	switch name {
	case theme.SizeNameText:
		return 14
	case theme.SizeNameHeadingText:
		return 22
	case theme.SizeNameSubHeadingText:
		return 17
	case theme.SizeNamePadding:
		return 7
	case theme.SizeNameInlineIcon:
		return 18
	default:
		return theme.DefaultTheme().Size(name)
	}
}
