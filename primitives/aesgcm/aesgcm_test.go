package primitives

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAESGCM(t *testing.T) {
	tests := []struct {
		name                        string
		plaintext                   string
		additionalAuthenticatedData string
		initializationVector        string
		key                         string
		expectedCiphertext          string
		expectedAuthenticationTag   string
	}{
		{
			name:                        "Test Case 1",
			plaintext:                   "",
			additionalAuthenticatedData: "",
			initializationVector:        "000000000000000000000000",
			key:                         "00000000000000000000000000000000",
			expectedCiphertext:          "",
			expectedAuthenticationTag:   "58e2fccefa7e3061367f1d57a4e7455a",
		},
		{
			name:                        "Test Case 2",
			plaintext:                   "00000000000000000000000000000000",
			additionalAuthenticatedData: "",
			initializationVector:        "000000000000000000000000",
			key:                         "00000000000000000000000000000000",
			expectedCiphertext:          "0388dace60b6a392f328c2b971b2fe78",
			expectedAuthenticationTag:   "ab6e47d42cec13bdf53a67b21257bddf",
		},
		{
			name:                        "Test Case 3",
			plaintext:                   "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
			additionalAuthenticatedData: "",
			initializationVector:        "cafebabefacedbaddecaf888",
			key:                         "feffe9928665731c6d6a8f9467308308",
			expectedCiphertext:          "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
			expectedAuthenticationTag:   "4d5c2af327cd64a62cf35abd2ba6fab4",
		},
		{
			name:                        "Test Case 4",
			plaintext:                   "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
			additionalAuthenticatedData: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
			initializationVector:        "cafebabefacedbaddecaf888",
			key:                         "feffe9928665731c6d6a8f9467308308",
			expectedCiphertext:          "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
			expectedAuthenticationTag:   "5bc94fbc3221a5db94fae95ae7121a47",
		},
		{
			name:                        "Test Case 5",
			plaintext:                   "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
			additionalAuthenticatedData: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
			initializationVector:        "cafebabefacedbad",
			key:                         "feffe9928665731c6d6a8f9467308308",
			expectedCiphertext:          "61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c742373806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598",
			expectedAuthenticationTag:   "3612d2e79e3b0785561be14aaca2fccb",
		},
		{
			name:                        "Test Case 6",
			plaintext:                   "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
			additionalAuthenticatedData: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
			initializationVector:        "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b",
			key:                         "feffe9928665731c6d6a8f9467308308",
			expectedCiphertext:          "8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca701e4a9a4fba43c90ccdcb281d48c7c6fd62875d2aca417034c34aee5",
			expectedAuthenticationTag:   "619cc5aefffe0bfa462af43c1699d050",
		},
		{
			name:                        "Test Case 7",
			plaintext:                   "",
			additionalAuthenticatedData: "",
			initializationVector:        "000000000000000000000000",
			key:                         "000000000000000000000000000000000000000000000000",
			expectedCiphertext:          "",
			expectedAuthenticationTag:   "cd33b28ac773f74ba00ed1f312572435",
		},
		{
			name:                        "Test Case 8",
			plaintext:                   "00000000000000000000000000000000",
			additionalAuthenticatedData: "",
			initializationVector:        "000000000000000000000000",
			key:                         "000000000000000000000000000000000000000000000000",
			expectedCiphertext:          "98e7247c07f0fe411c267e4384b0f600",
			expectedAuthenticationTag:   "2ff58d80033927ab8ef4d4587514f0fb",
		},
		{
			name:                        "Test Case 9",
			plaintext:                   "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
			additionalAuthenticatedData: "",
			initializationVector:        "cafebabefacedbaddecaf888",
			key:                         "feffe9928665731c6d6a8f9467308308feffe9928665731c",
			expectedCiphertext:          "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710acade256",
			expectedAuthenticationTag:   "9924a7c8587336bfb118024db8674a14",
		},
		{
			name:                        "Test Case 10",
			plaintext:                   "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
			additionalAuthenticatedData: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
			initializationVector:        "cafebabefacedbaddecaf888",
			key:                         "feffe9928665731c6d6a8f9467308308feffe9928665731c",
			expectedCiphertext:          "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710",
			expectedAuthenticationTag:   "2519498e80f1478f37ba55bd6d27618c",
		},
		{
			name:                        "Test Case 11",
			plaintext:                   "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
			additionalAuthenticatedData: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
			initializationVector:        "cafebabefacedbad",
			key:                         "feffe9928665731c6d6a8f9467308308feffe9928665731c",
			expectedCiphertext:          "0f10f599ae14a154ed24b36e25324db8c566632ef2bbb34f8347280fc4507057fddc29df9a471f75c66541d4d4dad1c9e93a19a58e8b473fa0f062f7",
			expectedAuthenticationTag:   "65dcc57fcf623a24094fcca40d3533f8",
		},
		{
			name:                        "Test Case 12",
			plaintext:                   "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
			additionalAuthenticatedData: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
			initializationVector:        "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b",
			key:                         "feffe9928665731c6d6a8f9467308308feffe9928665731c",
			expectedCiphertext:          "d27e88681ce3243c4830165a8fdcf9ff1de9a1d8e6b447ef6ef7b79828666e4581e79012af34ddd9e2f037589b292db3e67c036745fa22e7e9b7373b",
			expectedAuthenticationTag:   "dcf566ff291c25bbb8568fc3d376a6d9",
		},
		{
			name:                        "Test Case 13",
			plaintext:                   "",
			additionalAuthenticatedData: "",
			initializationVector:        "000000000000000000000000",
			key:                         "0000000000000000000000000000000000000000000000000000000000000000",
			expectedCiphertext:          "",
			expectedAuthenticationTag:   "530f8afbc74536b9a963b4f1c4cb738b",
		},
		{
			name:                        "Test Case 14",
			plaintext:                   "00000000000000000000000000000000",
			additionalAuthenticatedData: "",
			initializationVector:        "000000000000000000000000",
			key:                         "0000000000000000000000000000000000000000000000000000000000000000",
			expectedCiphertext:          "cea7403d4d606b6e074ec5d3baf39d18",
			expectedAuthenticationTag:   "d0d1c8a799996bf0265b98b5d48ab919",
		},
		{
			name:                        "Test Case 15",
			plaintext:                   "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
			additionalAuthenticatedData: "",
			initializationVector:        "cafebabefacedbaddecaf888",
			key:                         "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
			expectedCiphertext:          "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
			expectedAuthenticationTag:   "b094dac5d93471bdec1a502270e3cc6c",
		},
		{
			name:                        "Test Case 16",
			plaintext:                   "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
			additionalAuthenticatedData: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
			initializationVector:        "cafebabefacedbaddecaf888",
			key:                         "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
			expectedCiphertext:          "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
			expectedAuthenticationTag:   "76fc6ece0f4e1768cddf8853bb2d551b",
		},
		{
			name:                        "Test Case 17",
			plaintext:                   "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
			additionalAuthenticatedData: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
			initializationVector:        "cafebabefacedbad",
			key:                         "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
			expectedCiphertext:          "c3762df1ca787d32ae47c13bf19844cbaf1ae14d0b976afac52ff7d79bba9de0feb582d33934a4f0954cc2363bc73f7862ac430e64abe499f47c9b1f",
			expectedAuthenticationTag:   "3a337dbf46a792c45e454913fe2ea8f2",
		},
		{
			name:                        "Test Case 18",
			plaintext:                   "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
			additionalAuthenticatedData: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
			initializationVector:        "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b",
			key:                         "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
			expectedCiphertext:          "5a8def2f0c9e53f1f75d7853659e2a20eeb2b22aafde6419a058ab4f6f746bf40fc0c3b780f244452da3ebf1c5d82cdea2418997200ef82e44ae7e3f",
			expectedAuthenticationTag:   "a44a8266ee1c8eb0c8b5d4cf5ae9f19a",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plaintext, _ := hex.DecodeString(tt.plaintext)
			aad, _ := hex.DecodeString(tt.additionalAuthenticatedData)
			iv, _ := hex.DecodeString(tt.initializationVector)
			key, _ := hex.DecodeString(tt.key)
			expectedCiphertext, _ := hex.DecodeString(tt.expectedCiphertext)
			expectedAuthTag, _ := hex.DecodeString(tt.expectedAuthenticationTag)

			ciphertext, authTag, err := AESGCMEncrypt(plaintext, key, iv, aad)
			if err != nil {
				t.Fatalf("AESGCMEncrypt failed: %v", err)
			}

			if !bytes.Equal(ciphertext, expectedCiphertext) {
				t.Errorf("Ciphertext mismatch.\nGot:  %x\nWant: %x", ciphertext, expectedCiphertext)
			}

			if !bytes.Equal(authTag, expectedAuthTag) {
				t.Errorf("Authentication tag mismatch.\nGot:  %x\nWant: %x", authTag, expectedAuthTag)
			}
		})
	}
}

func TestGhash(t *testing.T) {
	input, _ := hex.DecodeString("000000000000000000000000000000000388dace60b6a392f328c2b971b2fe7800000000000000000000000000000080")
	hashSubKey, _ := hex.DecodeString("66e94bd4ef8a2c3b884cfa59ca342b2e")
	expected, _ := hex.DecodeString("f38cbb1ad69223dcc3457ae5b6b0f885")

	actual := Ghash(input, hashSubKey)

	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("ghash mismatch:\n got: %x\nwant: %x", actual, expected)
	}
}

func TestAES(t *testing.T) {
	t.Run("AES-128", func(t *testing.T) {
		plaintext, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
		key, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f") //NOSONAR test vector, not a real credential
		expected, _ := hex.DecodeString("69c4e0d86a7b0430d8cdb78070b4c55a")

		block, err := aes.NewCipher(key)
		require.NoError(t, err)

		result := make([]byte, len(plaintext))
		block.Encrypt(result, plaintext) //NOSONAR test verification of AES block cipher

		require.Equal(t, expected, result)
	})

	t.Run("AES-192", func(t *testing.T) {
		plaintext, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
		key, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f1011121314151617") //NOSONAR test vector, not a real credential
		expected, _ := hex.DecodeString("dda97ca4864cdfe06eaf70a0ec0d7191")

		block, err := aes.NewCipher(key)
		require.NoError(t, err)

		result := make([]byte, len(plaintext))
		block.Encrypt(result, plaintext) //NOSONAR test verification of AES block cipher

		require.Equal(t, expected, result)
	})

	t.Run("AES-256", func(t *testing.T) {
		plaintext, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
		key, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f") //NOSONAR test vector, not a real credential
		expected, _ := hex.DecodeString("8ea2b7ca516745bfeafc49904b496089")

		block, err := aes.NewCipher(key)
		require.NoError(t, err)

		result := make([]byte, len(plaintext))
		block.Encrypt(result, plaintext) //NOSONAR test verification of AES block cipher

		require.Equal(t, expected, result)
	})

	t.Run("Additional AES tests", func(t *testing.T) {
		testCases := []struct {
			plaintext string
			key       string
			expected  string
		}{
			{"00000000000000000000000000000000", "00000000000000000000000000000000", "66e94bd4ef8a2c3b884cfa59ca342b2e"},
			{"00000000000000000000000000000000", "000102030405060708090a0b0c0d0e0f", "c6a13b37878f5b826f4f8162a1c8d879"},
			{"00000000000000000000000000000000", "ad7a2bd03eac835a6f620fdcb506b345", "73a23d80121de2d5a850253fcf43120e"},
		}

		for _, tc := range testCases {
			plaintext, _ := hex.DecodeString(tc.plaintext)
			key, _ := hex.DecodeString(tc.key)
			expected, _ := hex.DecodeString(tc.expected)

			block, err := aes.NewCipher(key)
			require.NoError(t, err)

			result := make([]byte, len(plaintext))
			block.Encrypt(result, plaintext) //NOSONAR test verification of AES block cipher

			require.Equal(t, expected, result)
		}
	})
}
