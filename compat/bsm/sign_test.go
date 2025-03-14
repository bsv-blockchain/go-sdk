package compat_test

import (
	"encoding/base64"
	"fmt"
	"testing"

	compat "github.com/bsv-blockchain/go-sdk/compat/bsm"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
	"github.com/bsv-blockchain/go-sdk/script"
)

func TestSigningCompression(t *testing.T) {
	testKey, _ := ec.PrivateKeyFromHex("0499f8239bfe10eb0f5e53d543635a423c96529dd85fa4bad42049a0b435ebdd")
	testData := []byte("test message")

	// Test sign compressed
	address, err := script.NewAddressFromPublicKey(testKey.PubKey(), true)
	if err != nil {
		t.Errorf("Get address err %s", err)
	}
	sig, err := compat.SignMessage(testKey, testData)
	if err != nil {
		t.Errorf("Failed to sign compressed %s", err)
	}

	err = compat.VerifyMessage(address.AddressString, sig, testData)

	if err != nil {
		t.Errorf("Failed to validate compressed %s", err)
	}
}

// TestSignMessage will test the method SignMessage() and SignMessageString()
func TestSignMessage(t *testing.T) {
	t.Parallel()
	var tests = []struct {
		inputKey          string
		inputMessage      string
		expectedSignature string
		expectedError     bool
	}{
		{
			"0499f8239bfe10eb0f5e53d543635a423c96529dd85fa4bad42049a0b435ebdd",
			"test message",
			"IFxPx8JHsCiivB+DW/RgNpCLT6yG3j436cUNWKekV3ORBrHNChIjeVReyAco7PVmmDtVD3POs9FhDlm/nk5I6O8=",
			false,
		},
		{
			"ef0b8bad0be285099534277fde328f8f19b3be9cadcd4c08e6ac0b5f863745ac",
			"This is a test message",
			"H+zZagsyz7ioC/ZOa5EwsaKice0vs2BvZ0ljgkFHxD3vGsMlGeD4sXHEcfbI4h8lP29VitSBdf4A+nHXih7svf4=",
			false,
		},
		{
			"0499f8239bfe10eb0f5e53d543635a423c96529dd85fa4bad42049a0b435ebdd",
			"This time I'm writing a new message that is obnixiously long af. This time I'm writing a new message that is obnixiously long af. This time I'm writing a new message that is obnixiously long af. This time I'm writing a new message that is obnixiously long af. This time I'm writing a new message that is obnixiously long af. This time I'm writing a new message that is obnixiously long af. This time I'm writing a new message that is obnixiously long af. This time I'm writing a new message that is obnixiously long af. This time I'm writing a new message that is obnixiously long af. This time I'm writing a new message that is obnixiously long af. This time I'm writing a new message that is obnixiously long af. This time I'm writing a new message that is obnixiously long af. This time I'm writing a new message that is obnixiously long af. This time I'm writing a new message that is obnixiously long af.",
			"HxRcFXQc7LHxFNpK5lzhR+LF5ixIvhB089bxYzTAV02yGHm/3ALxltz/W4lGp77Q5UTxdj+TU+96mdAcJ5b/fGs=",
			false,
		},
		{
			"93596babb564cbbdc84f2370c710b9bcc94333495b60af719b5fcf9ba00ba82c",
			"This is a test message",
			"IIuDw09ffPgEDuxEw5yHVp1+mi4QpuhAwLyQdpMTfsHCOkMqTKXuP7dSNWMEJqZsiQ8eKMDRvf2wZ4e5bxcu4O0=",
			false,
		},
		{
			"50381cf8f52936faae4a05a073a03d688a9fa206d005e87a39da436c75476d78",
			"This is a test message",
			"ILBmbjCY2Z7eSXGXZoBI3x2ZRaYUYOGtEaDjXetaY+zNDtMOvagsOGEHnVT3f5kXlEbuvmPydHqLnyvZP3cDOWk=",
			false,
		},
		{
			"c7726663147afd1add392d129086e57c0b05aa66a6ded564433c04bd55741434",
			"This is a test message",
			"IOI207QUnTLr2Ll+s4kUxNgLgorkc/Z5Pc+XNvUBYLy2TxaU6oHEJ2TTJ1mZVrtUyHm6e315v1tIjeosW3Odfqw=",
			false,
		},
		{
			"c7726663147afd1add392d129086e57c0b05aa66a6ded564433c04bd55741434",
			"1",
			"IMcRFG1VNN9TDGXpCU+9CqKLNOuhwQiXI5hZpkTOuYHKBDOWayNuAABofYLqUHYTMiMf9mYFQ0sPgFJZz3F7ELQ=",
			false,
		},
		{
			"",
			"This is a test message",
			"",
			true,
		},
		{
			"0",
			"This is a test message",
			"",
			true,
		},
		{
			"0000000",
			"This is a test message",
			"",
			true,
		},
		{
			"c7726663147afd1add392d129086e57c0b",
			"This is a test message",
			"H6N+iPf23i2YkLsNzF/yyeBm9eSYBoY/HFV1Md1F0ElWBXW5E5mkdRtgjoRuq0yNb1CCFNWWlkn2gZknFJNUFJ8=",
			false,
		},
	}

	const failedUnexpectedError = "%d %s Failed: [%s] [%s] inputted and error not expected but got: %s"
	const failedExpectedError = "%d %s Failed: [%s] [%s] inputted and error was expected"
	const failedExpectedSignature = "%d %s Failed: [%s] [%s] inputted [%s] expected but got: %s"

	for idx, test := range tests {
		testPk, errKey := ec.PrivateKeyFromHex(test.inputKey)
		if signature, err := compat.SignMessage(testPk, []byte(test.inputMessage)); err != nil && !test.expectedError {
			t.Fatalf(failedUnexpectedError, idx, t.Name(), test.inputKey, test.inputMessage, err.Error())
		} else if err == nil && errKey == nil && test.expectedError {
			t.Fatalf(failedExpectedError, idx, t.Name(), test.inputKey, test.inputMessage)
		} else if base64.StdEncoding.EncodeToString(signature) != test.expectedSignature {
			t.Fatalf(failedExpectedSignature, idx, t.Name(), test.inputKey, test.inputMessage, test.expectedSignature, signature)
		}

		if sigStr, err := compat.SignMessageString(testPk, []byte(test.inputMessage)); err != nil && !test.expectedError {
			t.Fatalf(failedUnexpectedError, idx, t.Name(), test.inputKey, test.inputMessage, err.Error())
		} else if err == nil && errKey == nil && test.expectedError {
			t.Fatalf(failedExpectedError, idx, t.Name(), test.inputKey, test.inputMessage)
		} else if sigStr != test.expectedSignature {
			t.Fatalf(failedExpectedSignature, idx, t.Name(), test.inputKey, test.inputMessage, test.expectedSignature, sigStr)
		}

	}
}

func TestSignMessageUncompressed(t *testing.T) {
	t.Parallel()
	var tests = []struct {
		inputKey          string
		inputMessage      string
		expectedSignature string
		expectedError     bool
	}{
		{
			"0499f8239bfe10eb0f5e53d543635a423c96529dd85fa4bad42049a0b435ebdd",
			"test message",
			"HFxPx8JHsCiivB+DW/RgNpCLT6yG3j436cUNWKekV3ORBrHNChIjeVReyAco7PVmmDtVD3POs9FhDlm/nk5I6O8=",
			false,
		},
		{
			"ef0b8bad0be285099534277fde328f8f19b3be9cadcd4c08e6ac0b5f863745ac",
			"This is a test message",
			"G+zZagsyz7ioC/ZOa5EwsaKice0vs2BvZ0ljgkFHxD3vGsMlGeD4sXHEcfbI4h8lP29VitSBdf4A+nHXih7svf4=",
			false,
		},
		{
			"0499f8239bfe10eb0f5e53d543635a423c96529dd85fa4bad42049a0b435ebdd",
			"This time I'm writing a new message that is obnixiously long af. This time I'm writing a new message that is obnixiously long af. This time I'm writing a new message that is obnixiously long af. This time I'm writing a new message that is obnixiously long af. This time I'm writing a new message that is obnixiously long af. This time I'm writing a new message that is obnixiously long af. This time I'm writing a new message that is obnixiously long af. This time I'm writing a new message that is obnixiously long af. This time I'm writing a new message that is obnixiously long af. This time I'm writing a new message that is obnixiously long af. This time I'm writing a new message that is obnixiously long af. This time I'm writing a new message that is obnixiously long af. This time I'm writing a new message that is obnixiously long af. This time I'm writing a new message that is obnixiously long af.",
			"GxRcFXQc7LHxFNpK5lzhR+LF5ixIvhB089bxYzTAV02yGHm/3ALxltz/W4lGp77Q5UTxdj+TU+96mdAcJ5b/fGs=",
			false,
		},
		{
			"93596babb564cbbdc84f2370c710b9bcc94333495b60af719b5fcf9ba00ba82c",
			"This is a test message",
			"HIuDw09ffPgEDuxEw5yHVp1+mi4QpuhAwLyQdpMTfsHCOkMqTKXuP7dSNWMEJqZsiQ8eKMDRvf2wZ4e5bxcu4O0=",
			false,
		},
		{
			"50381cf8f52936faae4a05a073a03d688a9fa206d005e87a39da436c75476d78",
			"This is a test message",
			"HLBmbjCY2Z7eSXGXZoBI3x2ZRaYUYOGtEaDjXetaY+zNDtMOvagsOGEHnVT3f5kXlEbuvmPydHqLnyvZP3cDOWk=",
			false,
		},
		{
			"c7726663147afd1add392d129086e57c0b05aa66a6ded564433c04bd55741434",
			"This is a test message",
			"HOI207QUnTLr2Ll+s4kUxNgLgorkc/Z5Pc+XNvUBYLy2TxaU6oHEJ2TTJ1mZVrtUyHm6e315v1tIjeosW3Odfqw=",
			false,
		},
		{
			"c7726663147afd1add392d129086e57c0b05aa66a6ded564433c04bd55741434",
			"1",
			"HMcRFG1VNN9TDGXpCU+9CqKLNOuhwQiXI5hZpkTOuYHKBDOWayNuAABofYLqUHYTMiMf9mYFQ0sPgFJZz3F7ELQ=",
			false,
		},
		{
			"",
			"This is a test message",
			"",
			true,
		},
		{
			"0",
			"This is a test message",
			"",
			true,
		},
		{
			"0000000",
			"This is a test message",
			"",
			true,
		},
		{
			"c7726663147afd1add392d129086e57c0b",
			"This is a test message",
			"G6N+iPf23i2YkLsNzF/yyeBm9eSYBoY/HFV1Md1F0ElWBXW5E5mkdRtgjoRuq0yNb1CCFNWWlkn2gZknFJNUFJ8=",
			false,
		},
	}

	for idx, test := range tests {
		testPk, errKey := ec.PrivateKeyFromHex(test.inputKey)
		if signature, err := compat.SignMessageWithCompression(testPk, []byte(test.inputMessage), false); err != nil && !test.expectedError {
			t.Fatalf("%d %s Failed: [%s] [%s] inputted and error not expected but got: %s", idx, t.Name(), test.inputKey, test.inputMessage, err.Error())
		} else if err == nil && errKey == nil && test.expectedError {
			t.Fatalf("%d %s Failed: [%s] [%s] inputted and error was expected", idx, t.Name(), test.inputKey, test.inputMessage)
		} else if base64.StdEncoding.EncodeToString(signature) != test.expectedSignature {
			t.Fatalf("%d %s Failed: [%s] [%s] inputted [%s] expected but got: %s", idx, t.Name(), test.inputKey, test.inputMessage, test.expectedSignature, signature)
		}
	}
}

// ExampleSignMessage example using SignMessage()
func ExampleSignMessage() {
	pk, _ := ec.PrivateKeyFromHex("ef0b8bad0be285099534277fde328f8f19b3be9cadcd4c08e6ac0b5f863745ac")
	signature, err := compat.SignMessage(pk, []byte("This is a test message"))
	if err != nil {
		fmt.Printf("error occurred: %s", err.Error())
		return
	}
	fmt.Printf("signature created: %s", base64.StdEncoding.EncodeToString(signature))
	// Output:signature created: H+zZagsyz7ioC/ZOa5EwsaKice0vs2BvZ0ljgkFHxD3vGsMlGeD4sXHEcfbI4h8lP29VitSBdf4A+nHXih7svf4=
}

// BenchmarkSignMessage benchmarks the method SignMessage()
func BenchmarkSignMessage(b *testing.B) {
	key, _ := ec.NewPrivateKey()
	for i := 0; i < b.N; i++ {
		_, _ = compat.SignMessage(key, []byte("This is a test message"))
	}
}
