// Package bdk adapts go-sdk transactions and secp256k1 signatures to GoBDK's
// native implementations.
//
// GoBDK ships prebuilt native libraries. The native API is available only with
// CGO on supported Linux and macOS amd64/arm64 targets. On other targets this
// package remains discoverable for documentation and repository-wide tooling,
// but exposes no native implementation.
//
// Importing the package does not change SDK behavior; callers must explicitly
// install the signature backend or construct a Validator.
package bdk
