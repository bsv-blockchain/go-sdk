//go:build !cgo || ios || android || (!darwin && !linux) || (!amd64 && !arm64)

package main

import "fmt"

func main() {
	fmt.Println("GoBDK requires CGO on a supported Linux or macOS amd64/arm64 target")
}
