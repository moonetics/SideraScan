package main

//go:generate go run github.com/josephspurrier/goversioninfo/cmd/goversioninfo@v1.7.0 -64 -o resource.syso -icon ../../build/windows/siderascan.ico -application-icon ../../build/windows/siderascan.ico -manifest ../../build/windows/app.manifest -product-name SideraScan -description "SideraScan Scanner" -company SideraLabs -copyright "Copyright (c) SideraLabs" -internal-name SideraScan -original-name SideraScan.exe -product-version 0.1.0 -file-version 0.1.0.0 -propagate-ver-strings ../../build/windows/versioninfo.json
