package substrates

// Call represents the different types of wallet wire protocol operations.
// Each call type corresponds to a specific wallet function that can be invoked remotely.
type Call byte

const (
	CallCreateAction                 Call = 1
	CallSignAction                   Call = 2
	CallAbortAction                  Call = 3
	CallListActions                  Call = 4
	CallInternalizeAction            Call = 5
	CallListOutputs                  Call = 6
	CallRelinquishOutput             Call = 7
	CallGetPublicKey                 Call = 8
	CallRevealCounterpartyKeyLinkage Call = 9
	CallRevealSpecificKeyLinkage     Call = 10
	CallEncrypt                      Call = 11
	CallDecrypt                      Call = 12
	CallCreateHMAC                   Call = 13
	CallVerifyHMAC                   Call = 14
	CallCreateSignature              Call = 15
	CallVerifySignature              Call = 16
	CallAcquireCertificate           Call = 17
	CallListCertificates             Call = 18
	CallProveCertificate             Call = 19
	CallRelinquishCertificate        Call = 20
	CallDiscoverByIdentityKey        Call = 21
	CallDiscoverByAttributes         Call = 22
	CallIsAuthenticated              Call = 23
	CallWaitForAuthentication        Call = 24
	CallGetHeight                    Call = 25
	CallGetHeaderForHeight           Call = 26
	CallGetNetwork                   Call = 27
	CallGetVersion                   Call = 28
)
