package identity

import (
	"github.com/bsv-blockchain/go-sdk/wallet"
)

// DisplayableIdentity contains formatted identity information for display in UIs
type DisplayableIdentity struct {
	Name           string
	AvatarURL      string
	AbbreviatedKey string
	IdentityKey    string
	BadgeIconURL   string
	BadgeLabel     string
	BadgeClickURL  string
}

// DefaultIdentity provides fallback values for unknown identity types
var DefaultIdentity = DisplayableIdentity{
	Name:           "Unknown Identity",
	AvatarURL:      "XUUB8bbn9fEthk15Ge3zTQXypUShfC94vFjp65v7u5CQ8qkpxzst",
	IdentityKey:    "",
	AbbreviatedKey: "",
	BadgeIconURL:   "XUUV39HVPkpmMzYNTx7rpKzJvXfeiVyQWg2vfSpjBAuhunTCA9uG",
	BadgeLabel:     "Not verified by anyone you trust.",
	BadgeClickURL:  "https://projectbabbage.com/docs/unknown-identity",
}

// IdentityClientOptions configures the behavior of IdentityClient
type IdentityClientOptions struct {
	ProtocolID  wallet.Protocol
	KeyID       string
	TokenAmount uint64
	OutputIndex uint32
}

// KnownIdentityTypes catalogs recognized certificate types
var KnownIdentityTypes = struct {
	IdentiCert  string
	DiscordCert string
	PhoneCert   string
	XCert       string
	Registrant  string
	EmailCert   string
	Anyone      string
	Self        string
	CoolCert    string
}{
	IdentiCert:  "z40BOInXkI8m7f/wBrv4MJ09bZfzZbTj2fJqCtONqCY=",
	DiscordCert: "2TgqRC35B1zehGmB21xveZNc7i5iqHc0uxMb+1NMPW4=",
	PhoneCert:   "mffUklUzxbHr65xLohn0hRL0Tq2GjW1GYF/OPfzqJ6A=",
	XCert:       "vdDWvftf1H+5+ZprUw123kjHlywH+v20aPQTuXgMpNc=",
	Registrant:  "YoPsbfR6YQczjzPdHCoGC7nJsOdPQR50+SYqcWpJ0y0=",
	EmailCert:   "exOl3KM0dIJ04EW5pZgbZmPag6MdJXd3/a1enmUU/BA=",
	Anyone:      "mfkOMfLDQmrr3SBxBQ5WeE+6Hy3VJRFq6w4A5Ljtlis=",
	Self:        "Hkge6X5JRxt1cWXtHLCrSTg6dCVTxjQJJ48iOYd7n3g=",
	CoolCert:    "AGfk/WrT1eBDXpz3mcw386Zww2HmqcIn3uY6x4Af1eo=",
}

// CertificateFieldNameUnder50Bytes represents a certificate field name
type CertificateFieldNameUnder50Bytes string

// OriginatorDomainNameStringUnder250Bytes represents an originator domain
type OriginatorDomainNameStringUnder250Bytes string
