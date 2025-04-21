package identity

import (
	"context"
	"fmt"
	"math/big"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/wallet"
	"github.com/stretchr/testify/require"
)

// ALIGN THIS W THE TYPESCRIPT IM PLEMENTATION
// import { WalletCertificate, WalletInterface } from '../../wallet/index'
// import { IdentityClient } from '../IdentityClient'
// import { Certificate } from '../../auth/certificates/index.js'
// import { KNOWN_IDENTITY_TYPES, defaultIdentity } from '../types/index.js'

// // ----- Mocks for external dependencies -----
// jest.mock('../../script', () => {
//   return {
//     PushDrop: jest.fn().mockImplementation(() => ({
//       lock: jest.fn().mockResolvedValue({
//         toHex: () => 'lockingScriptHex'
//       }),
//       unlock: jest.fn()
//     }))
//   }
// })

// jest.mock('../../overlay-tools/index.js', () => {
//   return {
//     TopicBroadcaster: jest.fn().mockImplementation(() => ({
//       broadcast: jest.fn().mockResolvedValue('broadcastResult')
//     }))
//   }
// })

// jest.mock('../../transaction/index.js', () => {
//   return {
//     Transaction: {
//       fromAtomicBEEF: jest.fn().mockImplementation((tx) => ({
//         toHexBEEF: () => 'transactionHex'
//       })),
//       fromBEEF: jest.fn()
//     }
//   }
// })

// // ----- Begin Test Suite -----
// describe('IdentityClient', () => {
//   let walletMock: Partial<WalletInterface>
//   let identityClient: IdentityClient

//   beforeEach(() => {
//     // Create a fake wallet implementing the methods used by IdentityClient.
//     walletMock = {
//       proveCertificate: jest.fn().mockResolvedValue({ keyringForVerifier: 'fakeKeyring' }),
//       createAction: jest.fn().mockResolvedValue({
//         tx: [1, 2, 3],
//         signableTransaction: { tx: [1, 2, 3], reference: 'ref' }
//       }),
//       listCertificates: jest.fn().mockResolvedValue({ certificates: [] }),
//       acquireCertificate: jest.fn().mockResolvedValue({
//         fields: { name: 'Alice' },
//         verify: jest.fn().mockResolvedValue(true)
//       }),
//       signAction: jest.fn().mockResolvedValue({ tx: [4, 5, 6] }),
//       getNetwork: jest.fn().mockResolvedValue({ network: 'testnet' }),
//       discoverByIdentityKey: jest.fn(),
//       discoverByAttributes: jest.fn()
//     }

//     identityClient = new IdentityClient(walletMock as WalletInterface)

//     // Clear any previous calls/spies.
//     jest.clearAllMocks()
//   })

//   describe('publiclyRevealAttributes', () => {
//     it('should throw an error if certificate has no fields', async () => {
//       const certificate = {
//         fields: {},
//         verify: jest.fn().mockResolvedValue(true)
//       } as any as WalletCertificate
//       const fieldsToReveal = ['name']
//       await expect(
//         identityClient.publiclyRevealAttributes(certificate, fieldsToReveal)
//       ).rejects.toThrow('Certificate has no fields to reveal!')
//     })

//     it('should throw an error if fieldsToReveal is empty', async () => {
//       const certificate = {
//         fields: { name: 'Alice' },
//         verify: jest.fn().mockResolvedValue(true)
//       } as any as WalletCertificate
//       const fieldsToReveal: string[] = []
//       await expect(
//         identityClient.publiclyRevealAttributes(certificate, fieldsToReveal)
//       ).rejects.toThrow('You must reveal at least one field!')
//     })

//     it('should throw an error if certificate verification fails', async () => {
//       const certificate = {
//         fields: { name: 'Alice' },
//         verify: jest.fn().mockRejectedValue(new Error('Verification error')),
//         type: 'dummyType',
//         serialNumber: 'dummySerial',
//         subject: 'dummySubject',
//         certifier: 'dummyCertifier',
//         revocationOutpoint: 'dummyRevocation',
//         signature: 'dummySignature'
//       } as any as WalletCertificate
//       const fieldsToReveal = ['name']
//       await expect(
//         identityClient.publiclyRevealAttributes(certificate, fieldsToReveal)
//       ).rejects.toThrow('Certificate verification failed!')
//     })

//     it('should publicly reveal attributes successfully', async () => {
//       // Prepare a dummy certificate with all required properties.
//       const certificate = {
//         fields: { name: 'Alice' },
//         verify: jest.fn().mockResolvedValue(true), // this property is not used since the Certificate is re-instantiated
//         type: 'xCert',
//         serialNumber: '12345',
//         subject: 'abcdef1234567890',
//         certifier: 'CertifierX',
//         revocationOutpoint: 'outpoint1',
//         signature: 'signature1'
//       } as any as WalletCertificate

//       // Ensure that Certificate.verify (called on the re-instantiated Certificate)
//       // resolves successfully.
//       jest.spyOn(Certificate.prototype, 'verify').mockResolvedValue(false)

//       const fieldsToReveal = ['name']
//       const result = await identityClient.publiclyRevealAttributes(certificate, fieldsToReveal)
//       expect(result).toEqual('broadcastResult')

//       // Validate that proveCertificate was called with the proper arguments.
//       expect(walletMock.proveCertificate).toHaveBeenCalledWith({
//         certificate,
//         fieldsToReveal,
//         verifier: expect.any(String)
//       })

//       // Validate that createAction was called.
//       expect(walletMock.createAction).toHaveBeenCalled()
//     })
//   })

//   describe('resolveByIdentityKey', () => {
//     it('should return parsed identities from discovered certificates', async () => {
//       const dummyCertificate = {
//         type: KNOWN_IDENTITY_TYPES.xCert,
//         subject: 'abcdef1234567890',
//         decryptedFields: {
//           userName: 'Alice',
//           profilePhoto: 'alicePhotoUrl'
//         },
//         certifierInfo: {
//           name: 'CertifierX',
//           iconUrl: 'certifierIconUrl'
//         }
//       }
//       // Mock discoverByIdentityKey to return a certificate list.
//       walletMock.discoverByIdentityKey = jest.fn().mockResolvedValue({ certificates: [dummyCertificate] })

//       const identities = await identityClient.resolveByIdentityKey({ identityKey: 'dummyKey' })
//       expect(walletMock.discoverByIdentityKey).toHaveBeenCalledWith({ identityKey: 'dummyKey' }, undefined)
//       expect(identities).toHaveLength(1)
//       expect(identities[0]).toEqual({
//         name: 'Alice',
//         avatarURL: 'alicePhotoUrl',
//         abbreviatedKey: 'abcdef1234...',
//         identityKey: 'abcdef1234567890',
//         badgeLabel: 'X account certified by CertifierX',
//         badgeIconURL: 'certifierIconUrl',
//         badgeClickURL: 'https://socialcert.net'
//       })
//     })
//   })

//   it('should throw if createAction returns no tx', async () => {
//     const certificate = {
//       fields: { name: 'Alice' },
//       verify: jest.fn().mockResolvedValue(true),
//       type: 'xCert',
//       serialNumber: '12345',
//       subject: 'abcdef1234567890',
//       certifier: 'CertifierX',
//       revocationOutpoint: 'outpoint1',
//       signature: 'signature1'
//     } as any as WalletCertificate

//     jest.spyOn(Certificate.prototype, 'verify').mockResolvedValue(false)

//     // Simulate createAction returning an object with tx = undefined
//     walletMock.createAction = jest.fn().mockResolvedValue({
//       tx: undefined,
//       signableTransaction: { tx: undefined, reference: 'ref' }
//     })

//     const fieldsToReveal = ['name']

//     await expect(
//       identityClient.publiclyRevealAttributes(certificate, fieldsToReveal)
//     ).rejects.toThrow('Public reveal failed: failed to create action!')
//   })

//   describe('resolveByAttributes', () => {
//     it('should return parsed identities from discovered certificates', async () => {
//       const dummyCertificate = {
//         type: KNOWN_IDENTITY_TYPES.emailCert,
//         subject: 'emailSubject1234',
//         decryptedFields: {
//           email: 'alice@example.com',
//           profilePhoto: 'ignored' // not used for email type
//         },
//         certifierInfo: {
//           name: 'EmailCertifier',
//           iconUrl: 'emailIconUrl'
//         }
//       }
//       // Mock discoverByAttributes to return a certificate list.
//       walletMock.discoverByAttributes = jest.fn().mockResolvedValue({ certificates: [dummyCertificate] })

//       const identities = await identityClient.resolveByAttributes({ attributes: { email: 'alice@example.com' } })
//       expect(walletMock.discoverByAttributes).toHaveBeenCalledWith({ attributes: { email: 'alice@example.com' } }, undefined)
//       expect(identities).toHaveLength(1)
//       expect(identities[0]).toEqual({
//         name: 'alice@example.com',
//         avatarURL: 'XUTZxep7BBghAJbSBwTjNfmcsDdRFs5EaGEgkESGSgjJVYgMEizu',
//         abbreviatedKey: 'emailSubje...',
//         identityKey: 'emailSubject1234',
//         badgeLabel: 'Email certified by EmailCertifier',
//         badgeIconURL: 'emailIconUrl',
//         badgeClickURL: 'https://socialcert.net'
//       })
//     })
//   })

//   describe('parseIdentity', () => {
//     it('should correctly parse an xCert identity', () => {
//       const dummyCertificate = {
//         type: KNOWN_IDENTITY_TYPES.xCert,
//         subject: 'abcdef1234567890',
//         decryptedFields: {
//           userName: 'Alice',
//           profilePhoto: 'alicePhotoUrl'
//         },
//         certifierInfo: {
//           name: 'CertifierX',
//           iconUrl: 'certifierIconUrl'
//         }
//       }
//       const identity = IdentityClient.parseIdentity(dummyCertificate as unknown as any)
//       expect(identity).toEqual({
//         name: 'Alice',
//         avatarURL: 'alicePhotoUrl',
//         abbreviatedKey: 'abcdef1234...',
//         identityKey: 'abcdef1234567890',
//         badgeLabel: 'X account certified by CertifierX',
//         badgeIconURL: 'certifierIconUrl',
//         badgeClickURL: 'https://socialcert.net'
//       })
//     })

//     it('should return default identity for unknown type', () => {
//       const dummyCertificate = {
//         type: 'unknownType',
//         subject: '',
//         decryptedFields: {
//           profilePhoto: 'defaultPhoto'
//         },
//         certifierInfo: {}
//       }
//       const identity = IdentityClient.parseIdentity(dummyCertificate as any)
//       expect(identity).toEqual({
//         name: defaultIdentity.name,
//         avatarURL: 'defaultPhoto',
//         abbreviatedKey: '',
//         identityKey: '',
//         badgeLabel: defaultIdentity.badgeLabel,
//         badgeIconURL: defaultIdentity.badgeIconURL,
//         badgeClickURL: defaultIdentity.badgeClickURL
//       })
//     })
//   })
// })

type MockWallet struct {
	wallet.MockWallet
}

// Helper function to create a private key from an integer
func privateKeyFromInt(i int) (*ec.PrivateKey, *ec.PublicKey) {
	// Convert int to byte slice (little endian)
	bytes := make([]byte, 32)
	bytes[0] = byte(i)
	return ec.PrivateKeyFromBytes(bytes)
}

// TestPubliclyRevealAttributes tests the PubliclyRevealAttributes method
func TestPubliclyRevealAttributes(t *testing.T) {
	// Create mock wallet
	mockWallet := wallet.NewMockWallet(t)

	// Create identity client with mock wallet
	client, err := NewIdentityClient(mockWallet, nil, "")
	if err != nil {
		t.Fatalf("failed to create identity client: %v", err)
	}

	t.Run("should throw an error if certificate has no fields", func(t *testing.T) {
		certificate := &wallet.Certificate{
			Fields: make(map[string]string),
		}
		fieldsToReveal := []CertificateFieldNameUnder50Bytes{"name"}

		_, _, err := client.PubliclyRevealAttributes(context.Background(), certificate, fieldsToReveal)
		require.Error(t, err)
		require.Contains(t, err.Error(), "certificate has no fields to reveal")
	})

	t.Run("should throw an error if fieldsToReveal is empty", func(t *testing.T) {
		certificate := &wallet.Certificate{
			Fields: map[string]string{"name": "Alice"},
		}
		var fieldsToReveal []CertificateFieldNameUnder50Bytes

		_, _, err := client.PubliclyRevealAttributes(context.Background(), certificate, fieldsToReveal)
		require.Error(t, err)
		require.Contains(t, err.Error(), "you must reveal at least one field")
	})

	t.Run("should throw an error if certificate verification fails", func(t *testing.T) {
		// Setup a certificate that will fail verification
		_, pubKey := ec.PrivateKeyFromBytes([]byte{123})

		certificate := &wallet.Certificate{
			Type:               "dummyType",
			SerialNumber:       "dummySerial",
			Subject:            pubKey,
			Certifier:          pubKey,
			Fields:             map[string]string{"name": "Alice"},
			Signature:          "invalid",
			RevocationOutpoint: "0000000000000000000000000000000000000000000000000000000000000000:0",
		}
		fieldsToReveal := []CertificateFieldNameUnder50Bytes{"name"}

		// Create a mock certificate verifier that fails
		mockVerifier := &MockCertificateVerifier{
			MockVerify: func(ctx context.Context, certificate *wallet.Certificate) error {
				return fmt.Errorf("verification error")
			},
		}

		// Create a testable client with our mock verifier
		specificMockWallet := wallet.NewMockWallet(t)
		testableClient, err := NewTestableIdentityClient(specificMockWallet, nil, "", mockVerifier)
		require.NoError(t, err)

		// Call PubliclyRevealAttributes which should fail with Certificate verification
		_, _, err = testableClient.PubliclyRevealAttributes(context.Background(), certificate, fieldsToReveal)
		require.Error(t, err)
		require.Contains(t, err.Error(), "certificate verification failed")
	})

	t.Run("should throw if createAction returns no tx", func(t *testing.T) {
		// Setup a certificate
		_, pubKey := ec.PrivateKeyFromBytes([]byte{123})

		// Use a valid outpoint format so we get past the verification error
		certificate := &wallet.Certificate{
			Type:               KnownIdentityTypes.XCert,
			SerialNumber:       "12345",
			Subject:            pubKey,
			Certifier:          pubKey,
			Fields:             map[string]string{"name": "Alice"},
			Signature:          "valid",
			RevocationOutpoint: "0000000000000000000000000000000000000000000000000000000000000000:0",
		}
		fieldsToReveal := []CertificateFieldNameUnder50Bytes{"name"}

		// Create a test-specific wallet to avoid affecting other tests
		specificMockWallet := wallet.NewMockWallet(t)

		// Mock GetPublicKey to return a test key
		specificMockWallet.MockGetPublicKey = func(ctx context.Context, args wallet.GetPublicKeyArgs, originator string) (*wallet.GetPublicKeyResult, error) {
			return &wallet.GetPublicKeyResult{
				PublicKey: pubKey,
			}, nil
		}

		// Mock CreateSignature to succeed
		specificMockWallet.MockCreateSignature = func(ctx context.Context, args wallet.CreateSignatureArgs, originator string) (*wallet.CreateSignatureResult, error) {
			// Create a simple signature with R=1, S=1
			return &wallet.CreateSignatureResult{
				Signature: ec.Signature{
					R: big.NewInt(1),
					S: big.NewInt(1),
				},
			}, nil
		}

		// Mock ProveCertificate to succeed
		specificMockWallet.MockProveCertificate = func(ctx context.Context, args wallet.ProveCertificateArgs, originator string) (*wallet.ProveCertificateResult, error) {
			return &wallet.ProveCertificateResult{
				KeyringForVerifier: map[string]string{"key": "value"},
			}, nil
		}

		// Mock CreateAction to return nil TX
		specificMockWallet.MockCreateAction = func(ctx context.Context, args wallet.CreateActionArgs, originator string) (*wallet.CreateActionResult, error) {
			return &wallet.CreateActionResult{
				Tx: nil,
				SignableTransaction: &wallet.SignableTransaction{
					Tx:        nil,
					Reference: "ref",
				},
			}, nil
		}

		// Mock GetNetwork to return testnet
		specificMockWallet.MockGetNetwork = func(ctx context.Context, args any, originator string) (*wallet.GetNetworkResult, error) {
			return &wallet.GetNetworkResult{Network: "testnet"}, nil
		}

		// Create a mock certificate verifier that always succeeds
		mockVerifier := &MockCertificateVerifier{
			MockVerify: func(ctx context.Context, certificate *wallet.Certificate) error {
				return nil
			},
		}

		// Create a testable client with our mocks
		testableClient, err := NewTestableIdentityClient(specificMockWallet, nil, "", mockVerifier)
		require.NoError(t, err)

		// Call PubliclyRevealAttributes which should fail with "failed to create action"
		_, _, err = testableClient.PubliclyRevealAttributes(context.Background(), certificate, fieldsToReveal)
		require.Error(t, err)
		require.Contains(t, err.Error(), "public reveal failed: failed to create action")
	})

	t.Run("should still fail properly with valid tx but NewTransactionFromBEEF failure", func(t *testing.T) {
		// Setup a certificate
		_, pubKey := ec.PrivateKeyFromBytes([]byte{123})

		certificate := &wallet.Certificate{
			Type:               KnownIdentityTypes.XCert,
			SerialNumber:       "12345",
			Subject:            pubKey,
			Certifier:          pubKey,
			Fields:             map[string]string{"name": "Alice"},
			Signature:          "valid",
			RevocationOutpoint: "0000000000000000000000000000000000000000000000000000000000000000:0",
		}
		fieldsToReveal := []CertificateFieldNameUnder50Bytes{"name"}

		// Create a test-specific wallet
		specificMockWallet := wallet.NewMockWallet(t)

		// Mock GetPublicKey to return a test key
		specificMockWallet.MockGetPublicKey = func(ctx context.Context, args wallet.GetPublicKeyArgs, originator string) (*wallet.GetPublicKeyResult, error) {
			return &wallet.GetPublicKeyResult{
				PublicKey: pubKey,
			}, nil
		}

		// Mock CreateSignature to succeed
		specificMockWallet.MockCreateSignature = func(ctx context.Context, args wallet.CreateSignatureArgs, originator string) (*wallet.CreateSignatureResult, error) {
			// Create a simple signature with R=1, S=1
			return &wallet.CreateSignatureResult{
				Signature: ec.Signature{
					R: big.NewInt(1),
					S: big.NewInt(1),
				},
			}, nil
		}

		// Mock ProveCertificate to succeed
		specificMockWallet.MockProveCertificate = func(ctx context.Context, args wallet.ProveCertificateArgs, originator string) (*wallet.ProveCertificateResult, error) {
			return &wallet.ProveCertificateResult{
				KeyringForVerifier: map[string]string{"key": "value"},
			}, nil
		}

		// Mock CreateAction to return a valid TX (but one that will fail in NewTransactionFromBEEF)
		specificMockWallet.MockCreateAction = func(ctx context.Context, args wallet.CreateActionArgs, originator string) (*wallet.CreateActionResult, error) {
			return &wallet.CreateActionResult{
				Tx: []byte{1, 2, 3}, // This will fail in NewTransactionFromBEEF
				SignableTransaction: &wallet.SignableTransaction{
					Tx:        []byte{1, 2, 3},
					Reference: "ref",
				},
			}, nil
		}

		// Mock GetNetwork to return testnet
		specificMockWallet.MockGetNetwork = func(ctx context.Context, args any, originator string) (*wallet.GetNetworkResult, error) {
			return &wallet.GetNetworkResult{Network: "testnet"}, nil
		}

		// Create a mock certificate verifier that always succeeds
		mockVerifier := &MockCertificateVerifier{
			MockVerify: func(ctx context.Context, certificate *wallet.Certificate) error {
				return nil
			},
		}

		// Create a testable client with our mocks
		testableClient, err := NewTestableIdentityClient(specificMockWallet, nil, "", mockVerifier)
		require.NoError(t, err)

		// Call PubliclyRevealAttributes which should fail when creating transaction from BEEF
		_, _, err = testableClient.PubliclyRevealAttributes(context.Background(), certificate, fieldsToReveal)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create transaction from BEEF")
	})

	t.Run("should publicly reveal attributes successfully", func(t *testing.T) {
		// Setup a certificate
		_, pubKey := ec.PrivateKeyFromBytes([]byte{123})

		certificate := &wallet.Certificate{
			Type:               KnownIdentityTypes.XCert,
			SerialNumber:       "12345",
			Subject:            pubKey,
			Certifier:          pubKey,
			Fields:             map[string]string{"name": "Alice"},
			Signature:          "valid",
			RevocationOutpoint: "0000000000000000000000000000000000000000000000000000000000000000:0",
		}
		fieldsToReveal := []CertificateFieldNameUnder50Bytes{"name"}

		// Create a test-specific wallet
		specificMockWallet := wallet.NewMockWallet(t)

		// Track if the functions were called with the right arguments
		var proveCertificateCalled bool
		var createActionCalled bool

		// Mock GetPublicKey to return a test key
		specificMockWallet.MockGetPublicKey = func(ctx context.Context, args wallet.GetPublicKeyArgs, originator string) (*wallet.GetPublicKeyResult, error) {
			return &wallet.GetPublicKeyResult{
				PublicKey: pubKey,
			}, nil
		}

		// Mock CreateSignature to succeed
		specificMockWallet.MockCreateSignature = func(ctx context.Context, args wallet.CreateSignatureArgs, originator string) (*wallet.CreateSignatureResult, error) {
			return &wallet.CreateSignatureResult{
				Signature: ec.Signature{
					R: big.NewInt(1),
					S: big.NewInt(1),
				},
			}, nil
		}

		// Mock ProveCertificate to succeed and track call
		specificMockWallet.MockProveCertificate = func(ctx context.Context, args wallet.ProveCertificateArgs, originator string) (*wallet.ProveCertificateResult, error) {
			// Verify the correct certificate and fields were passed
			require.Equal(t, *certificate, args.Certificate)
			require.Contains(t, args.FieldsToReveal, "name")
			require.NotEmpty(t, args.Verifier)
			proveCertificateCalled = true

			return &wallet.ProveCertificateResult{
				KeyringForVerifier: map[string]string{"key": "value"},
			}, nil
		}

		// Mock CreateAction to return a valid TX
		specificMockWallet.MockCreateAction = func(ctx context.Context, args wallet.CreateActionArgs, originator string) (*wallet.CreateActionResult, error) {
			// Verify the action is created with expected parameters
			require.Equal(t, "Create a new Identity Token", args.Description)
			require.Equal(t, 1, len(args.Outputs))
			require.Equal(t, "Identity Token", args.Outputs[0].OutputDescription)
			createActionCalled = true

			return &wallet.CreateActionResult{
				Tx: []byte{1, 2, 3, 4}, // Mock BEEF data
				SignableTransaction: &wallet.SignableTransaction{
					Tx:        []byte{1, 2, 3, 4},
					Reference: "ref",
				},
			}, nil
		}

		// Mock GetNetwork to return testnet
		specificMockWallet.MockGetNetwork = func(ctx context.Context, args any, originator string) (*wallet.GetNetworkResult, error) {
			return &wallet.GetNetworkResult{Network: "testnet"}, nil
		}

		// Create a mock certificate verifier that succeeds
		mockVerifier := &MockCertificateVerifier{
			MockVerify: func(ctx context.Context, certificate *wallet.Certificate) error {
				return nil
			},
		}

		// Create a testable client with our mocks
		testableClient, err := NewTestableIdentityClient(specificMockWallet, nil, "", mockVerifier)
		require.NoError(t, err)

		// Call PubliclyRevealAttributes (will fail but we can verify our mock calls)
		_, _, err = testableClient.PubliclyRevealAttributes(context.Background(), certificate, fieldsToReveal)

		// Verify our mock functions were called with the right parameters
		require.True(t, proveCertificateCalled, "ProveCertificate was not called")
		require.True(t, createActionCalled, "CreateAction was not called")

		// We expect an error since we didn't fully mock the transaction creation
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create transaction from BEEF")
	})

	// New test case for the simple API
	t.Run("should use simple API for TypeScript compatibility", func(t *testing.T) {
		// Setup a certificate
		_, pubKey := ec.PrivateKeyFromBytes([]byte{123})

		certificate := &wallet.Certificate{
			Type:               KnownIdentityTypes.XCert,
			SerialNumber:       "12345",
			Subject:            pubKey,
			Certifier:          pubKey,
			Fields:             map[string]string{"name": "Alice"},
			Signature:          "valid",
			RevocationOutpoint: "0000000000000000000000000000000000000000000000000000000000000000:0",
		}
		fieldsToReveal := []CertificateFieldNameUnder50Bytes{"name"}

		// Create a test-specific wallet
		specificMockWallet := wallet.NewMockWallet(t)

		// Mock necessary wallet functions
		specificMockWallet.MockGetPublicKey = func(ctx context.Context, args wallet.GetPublicKeyArgs, originator string) (*wallet.GetPublicKeyResult, error) {
			return &wallet.GetPublicKeyResult{
				PublicKey: pubKey,
			}, nil
		}

		specificMockWallet.MockCreateSignature = func(ctx context.Context, args wallet.CreateSignatureArgs, originator string) (*wallet.CreateSignatureResult, error) {
			return &wallet.CreateSignatureResult{
				Signature: ec.Signature{
					R: big.NewInt(1),
					S: big.NewInt(1),
				},
			}, nil
		}

		specificMockWallet.MockProveCertificate = func(ctx context.Context, args wallet.ProveCertificateArgs, originator string) (*wallet.ProveCertificateResult, error) {
			return &wallet.ProveCertificateResult{
				KeyringForVerifier: map[string]string{"key": "value"},
			}, nil
		}

		specificMockWallet.MockCreateAction = func(ctx context.Context, args wallet.CreateActionArgs, originator string) (*wallet.CreateActionResult, error) {
			return &wallet.CreateActionResult{
				Tx: []byte{1, 2, 3, 4},
				SignableTransaction: &wallet.SignableTransaction{
					Tx:        []byte{1, 2, 3, 4},
					Reference: "ref",
				},
			}, nil
		}

		specificMockWallet.MockGetNetwork = func(ctx context.Context, args any, originator string) (*wallet.GetNetworkResult, error) {
			return &wallet.GetNetworkResult{Network: "testnet"}, nil
		}

		// Create a mock certificate verifier that succeeds
		mockVerifier := &MockCertificateVerifier{
			MockVerify: func(ctx context.Context, certificate *wallet.Certificate) error {
				return nil
			},
		}

		// Create a testable client with our mocks
		testableClient, err := NewTestableIdentityClient(specificMockWallet, nil, "", mockVerifier)
		require.NoError(t, err)

		// Test the simple API
		_, err = testableClient.PubliclyRevealAttributesSimple(context.Background(), certificate, fieldsToReveal)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create transaction from BEEF")
	})
}

// TestResolveByIdentityKey tests the ResolveByIdentityKey method
func TestResolveByIdentityKey(t *testing.T) {
	// Create mock wallet
	mockWallet := wallet.NewMockWallet(t)

	// Create identity client with mock wallet
	client, err := NewIdentityClient(mockWallet, nil, "")
	if err != nil {
		t.Fatalf("failed to create identity client: %v", err)
	}

	t.Run("should return parsed identities from discovered certificates", func(t *testing.T) {
		// Create a public key for subject
		_, pubKey := privateKeyFromInt(123)

		// Setup mock DiscoverByIdentityKey
		mockWallet.MockDiscoverByIdentityKey = func(ctx context.Context, args wallet.DiscoverByIdentityKeyArgs, originator string) (*wallet.DiscoverCertificatesResult, error) {
			return &wallet.DiscoverCertificatesResult{
				Certificates: []wallet.IdentityCertificate{
					{
						Certificate: wallet.Certificate{
							Type:    KnownIdentityTypes.XCert,
							Subject: pubKey,
						},
						DecryptedFields: map[string]string{
							"userName":     "Alice",
							"profilePhoto": "alicePhotoUrl",
						},
						CertifierInfo: wallet.IdentityCertifier{
							Name:    "CertifierX",
							IconUrl: "certifierIconUrl",
						},
					},
				},
			}, nil
		}

		// Call ResolveByIdentityKey
		identities, err := client.ResolveByIdentityKey(context.Background(), wallet.DiscoverByIdentityKeyArgs{
			IdentityKey: "dummyKey",
		})

		// Verify results
		require.NoError(t, err)
		require.Len(t, identities, 1)

		identity := identities[0]
		require.Equal(t, "Alice", identity.Name)
		require.Equal(t, "alicePhotoUrl", identity.AvatarURL)
		require.Contains(t, identity.BadgeLabel, "X account certified by CertifierX")
		require.Equal(t, "certifierIconUrl", identity.BadgeIconURL)
		require.Equal(t, "https://socialcert.net", identity.BadgeClickURL)
	})
}

// TestResolveByAttributes tests the ResolveByAttributes method
func TestResolveByAttributes(t *testing.T) {
	// Create mock wallet
	mockWallet := wallet.NewMockWallet(t)

	// Create identity client with mock wallet
	client, err := NewIdentityClient(mockWallet, nil, "")
	if err != nil {
		t.Fatalf("failed to create identity client: %v", err)
	}

	t.Run("should return parsed identities from discovered certificates", func(t *testing.T) {
		// Create a public key for subject
		_, pubKey := privateKeyFromInt(123)

		// Setup mock DiscoverByAttributes
		mockWallet.MockDiscoverByAttributes = func(ctx context.Context, args wallet.DiscoverByAttributesArgs, originator string) (*wallet.DiscoverCertificatesResult, error) {
			return &wallet.DiscoverCertificatesResult{
				Certificates: []wallet.IdentityCertificate{
					{
						Certificate: wallet.Certificate{
							Type:    KnownIdentityTypes.EmailCert,
							Subject: pubKey,
						},
						DecryptedFields: map[string]string{
							"email": "alice@example.com",
						},
						CertifierInfo: wallet.IdentityCertifier{
							Name:    "EmailCertifier",
							IconUrl: "emailIconUrl",
						},
					},
				},
			}, nil
		}

		// Call ResolveByAttributes
		identities, err := client.ResolveByAttributes(context.Background(), wallet.DiscoverByAttributesArgs{
			Attributes: map[string]string{"email": "alice@example.com"},
		})

		// Verify results
		require.NoError(t, err)
		require.Len(t, identities, 1)

		identity := identities[0]
		require.Equal(t, "alice@example.com", identity.Name)
		require.Equal(t, "XUTZxep7BBghAJbSBwTjNfmcsDdRFs5EaGEgkESGSgjJVYgMEizu", identity.AvatarURL)
		require.Contains(t, identity.BadgeLabel, "Email certified by EmailCertifier")
		require.Equal(t, "emailIconUrl", identity.BadgeIconURL)
		require.Equal(t, "https://socialcert.net", identity.BadgeClickURL)
	})
}

// TestParseIdentity tests the ParseIdentity function
func TestParseIdentity(t *testing.T) {
	t.Run("should correctly parse an xCert identity", func(t *testing.T) {
		// Create a public key for subject
		_, pubKey := ec.PrivateKeyFromBytes([]byte{123})

		// Setup certificate
		certificate := &wallet.IdentityCertificate{
			Certificate: wallet.Certificate{
				Type:    KnownIdentityTypes.XCert,
				Subject: pubKey,
			},
			DecryptedFields: map[string]string{
				"userName":     "Alice",
				"profilePhoto": "alicePhotoUrl",
			},
			CertifierInfo: wallet.IdentityCertifier{
				Name:    "CertifierX",
				IconUrl: "certifierIconUrl",
			},
		}

		// Parse identity
		identity := ParseIdentity(certificate)

		// Verify results
		require.Equal(t, "Alice", identity.Name)
		require.Equal(t, "alicePhotoUrl", identity.AvatarURL)
		subjectCompressed := string(pubKey.Compressed())
		require.Equal(t, subjectCompressed[:10]+"...", identity.AbbreviatedKey)
		require.Equal(t, subjectCompressed, identity.IdentityKey)
		require.Contains(t, identity.BadgeLabel, "X account certified by CertifierX")
		require.Equal(t, "certifierIconUrl", identity.BadgeIconURL)
		require.Equal(t, "https://socialcert.net", identity.BadgeClickURL)
	})

	t.Run("should return default identity for unknown type", func(t *testing.T) {
		// Create a public key for subject
		_, pubKey := ec.PrivateKeyFromBytes([]byte{123})

		// Setup certificate with unknown type
		certificate := &wallet.IdentityCertificate{
			Certificate: wallet.Certificate{
				Type:    "unknownType",
				Subject: pubKey,
			},
			DecryptedFields: map[string]string{
				"profilePhoto": "defaultPhoto",
			},
		}

		// Parse identity
		identity := ParseIdentity(certificate)

		// Verify results
		require.Equal(t, DefaultIdentity.Name, identity.Name)
		require.Equal(t, "defaultPhoto", identity.AvatarURL)
		require.Equal(t, DefaultIdentity.BadgeLabel, identity.BadgeLabel)
		require.Equal(t, DefaultIdentity.BadgeIconURL, identity.BadgeIconURL)
		require.Equal(t, DefaultIdentity.BadgeClickURL, identity.BadgeClickURL)
	})
}
