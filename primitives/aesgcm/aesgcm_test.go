package primitives

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

// gcmTestVector holds AES-GCM test data: name, plaintext, AAD, IV, key, expected ciphertext, expected auth tag.
type gcmTestVector struct {
	name, plaintext, aad, iv, key, ciphertext, authTag string
}

// gcmTestVectors returns the standard NIST AES-GCM test vectors.
// Extracted to a function to avoid SonarCloud flagging repetitive struct literals as duplication.
func gcmTestVectors() []gcmTestVector {
	return []gcmTestVector{
		{"Test Case 1", "", "", "000000000000000000000000", "00000000000000000000000000000000", "", "58e2fccefa7e3061367f1d57a4e7455a"},
		{"Test Case 2", "00000000000000000000000000000000", "", "000000000000000000000000", "00000000000000000000000000000000", "0388dace60b6a392f328c2b971b2fe78", "ab6e47d42cec13bdf53a67b21257bddf"},
		{"Test Case 3", "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255", "", "cafebabefacedbaddecaf888", "feffe9928665731c6d6a8f9467308308", "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985", "4d5c2af327cd64a62cf35abd2ba6fab4"},
		{"Test Case 4", "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39", "feedfacedeadbeeffeedfacedeadbeefabaddad2", "cafebabefacedbaddecaf888", "feffe9928665731c6d6a8f9467308308", "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091", "5bc94fbc3221a5db94fae95ae7121a47"},
		{"Test Case 5", "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39", "feedfacedeadbeeffeedfacedeadbeefabaddad2", "cafebabefacedbad", "feffe9928665731c6d6a8f9467308308", "61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c742373806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598", "3612d2e79e3b0785561be14aaca2fccb"},
		{"Test Case 6", "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39", "feedfacedeadbeeffeedfacedeadbeefabaddad2", "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b", "feffe9928665731c6d6a8f9467308308", "8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca701e4a9a4fba43c90ccdcb281d48c7c6fd62875d2aca417034c34aee5", "619cc5aefffe0bfa462af43c1699d050"},
		{"Test Case 7", "", "", "000000000000000000000000", "000000000000000000000000000000000000000000000000", "", "cd33b28ac773f74ba00ed1f312572435"},
		{"Test Case 8", "00000000000000000000000000000000", "", "000000000000000000000000", "000000000000000000000000000000000000000000000000", "98e7247c07f0fe411c267e4384b0f600", "2ff58d80033927ab8ef4d4587514f0fb"},
		{"Test Case 9", "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255", "", "cafebabefacedbaddecaf888", "feffe9928665731c6d6a8f9467308308feffe9928665731c", "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710acade256", "9924a7c8587336bfb118024db8674a14"},
		{"Test Case 10", "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39", "feedfacedeadbeeffeedfacedeadbeefabaddad2", "cafebabefacedbaddecaf888", "feffe9928665731c6d6a8f9467308308feffe9928665731c", "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710", "2519498e80f1478f37ba55bd6d27618c"},
		{"Test Case 11", "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39", "feedfacedeadbeeffeedfacedeadbeefabaddad2", "cafebabefacedbad", "feffe9928665731c6d6a8f9467308308feffe9928665731c", "0f10f599ae14a154ed24b36e25324db8c566632ef2bbb34f8347280fc4507057fddc29df9a471f75c66541d4d4dad1c9e93a19a58e8b473fa0f062f7", "65dcc57fcf623a24094fcca40d3533f8"},
		{"Test Case 12", "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39", "feedfacedeadbeeffeedfacedeadbeefabaddad2", "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b", "feffe9928665731c6d6a8f9467308308feffe9928665731c", "d27e88681ce3243c4830165a8fdcf9ff1de9a1d8e6b447ef6ef7b79828666e4581e79012af34ddd9e2f037589b292db3e67c036745fa22e7e9b7373b", "dcf566ff291c25bbb8568fc3d376a6d9"},
		{"Test Case 13", "", "", "000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000", "", "530f8afbc74536b9a963b4f1c4cb738b"},
		{"Test Case 14", "00000000000000000000000000000000", "", "000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000", "cea7403d4d606b6e074ec5d3baf39d18", "d0d1c8a799996bf0265b98b5d48ab919"},
		{"Test Case 15", "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255", "", "cafebabefacedbaddecaf888", "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308", "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad", "b094dac5d93471bdec1a502270e3cc6c"},
		{"Test Case 16", "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39", "feedfacedeadbeeffeedfacedeadbeefabaddad2", "cafebabefacedbaddecaf888", "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308", "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662", "76fc6ece0f4e1768cddf8853bb2d551b"},
		{"Test Case 17", "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39", "feedfacedeadbeeffeedfacedeadbeefabaddad2", "cafebabefacedbad", "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308", "c3762df1ca787d32ae47c13bf19844cbaf1ae14d0b976afac52ff7d79bba9de0feb582d33934a4f0954cc2363bc73f7862ac430e64abe499f47c9b1f", "3a337dbf46a792c45e454913fe2ea8f2"},
		{"Test Case 18", "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39", "feedfacedeadbeeffeedfacedeadbeefabaddad2", "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b", "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308", "5a8def2f0c9e53f1f75d7853659e2a20eeb2b22aafde6419a058ab4f6f746bf40fc0c3b780f244452da3ebf1c5d82cdea2418997200ef82e44ae7e3f", "a44a8266ee1c8eb0c8b5d4cf5ae9f19a"},
	}
}

func TestAESGCM(t *testing.T) {
	tests := gcmTestVectors()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plaintext, _ := hex.DecodeString(tt.plaintext)
			aad, _ := hex.DecodeString(tt.aad)
			iv, _ := hex.DecodeString(tt.iv)
			key, _ := hex.DecodeString(tt.key)
			expectedCiphertext, _ := hex.DecodeString(tt.ciphertext)
			expectedAuthTag, _ := hex.DecodeString(tt.authTag)

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
	testCases := []struct {
		name      string
		plaintext string
		key       string
		expected  string
	}{
		{"AES-128", "00112233445566778899aabbccddeeff", "000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a"},                                 //NOSONAR test vectors
		{"AES-192", "00112233445566778899aabbccddeeff", "000102030405060708090a0b0c0d0e0f1011121314151617", "dda97ca4864cdfe06eaf70a0ec0d7191"},                 //NOSONAR test vectors
		{"AES-256", "00112233445566778899aabbccddeeff", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "8ea2b7ca516745bfeafc49904b496089"}, //NOSONAR test vectors
		{"AES-128 zero plaintext", "00000000000000000000000000000000", "00000000000000000000000000000000", "66e94bd4ef8a2c3b884cfa59ca342b2e"},                  //NOSONAR test vectors
		{"AES-128 sequential key", "00000000000000000000000000000000", "000102030405060708090a0b0c0d0e0f", "c6a13b37878f5b826f4f8162a1c8d879"},                  //NOSONAR test vectors
		{"AES-128 random key", "00000000000000000000000000000000", "ad7a2bd03eac835a6f620fdcb506b345", "73a23d80121de2d5a850253fcf43120e"},                      //NOSONAR test vectors
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			plaintext, _ := hex.DecodeString(tc.plaintext)
			key, _ := hex.DecodeString(tc.key)
			expected, _ := hex.DecodeString(tc.expected)

			block, err := aes.NewCipher(key)
			require.NoError(t, err)

			result := make([]byte, len(plaintext))
			block.Encrypt(result, plaintext) //NOSONAR test verification of AES block cipher

			require.Equal(t, expected, result)
		})
	}
}
