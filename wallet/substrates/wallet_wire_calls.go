package substrates

type Call byte

const (
	CallCreateAction                 Call = 0x01
	CallSignAction                   Call = 0x02
	CallAbortAction                  Call = 0x03
	CallListActions                  Call = 0x04
	CallInternalizeAction            Call = 0x05
	CallListOutputs                  Call = 0x06
	CallRelinquishOutput             Call = 0x07
	CallGetPublicKey                 Call = 0x08
	CallRevealCounterpartyKeyLinkage Call = 0x09
	CallRevealSpecificKeyLinkage     Call = 0x10
	CallEncrypt                      Call = 0x11
	CallDecrypt                      Call = 0x12
	CallCreateHMAC                   Call = 0x13
	CallVerifyHMAC                   Call = 0x14
	CallCreateSignature              Call = 0x15
	CallVerifySignature              Call = 0x16
	CallAcquireCertificate           Call = 0x17
	CallListCertificates             Call = 0x18
	CallProveCertificate             Call = 0x19
	CallRelinquishCertificate        Call = 0x20
	CallDiscoverByIdentityKey        Call = 0x21
	CallDiscoverByAttributes         Call = 0x22
	CallIsAuthenticated              Call = 0x23
	CallWaitForAuthentication        Call = 0x24
	CallGetHeight                    Call = 0x25
	CallGetHeaderForHeight           Call = 0x26
	CallGetNetwork                   Call = 0x27
	CallGetVersion                   Call = 0x28
)
