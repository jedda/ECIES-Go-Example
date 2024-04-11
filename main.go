// This example Go code is designed to illustrate the usage of the [ECIES Go Module]
// Additionally, you can use it alongside the [ECIES Swift Playground]
// in order to play with and learn more about ECIES encryption on Apple platforms.
//
// [ECIES Go Module]: https://github.com/jedda/ecies
// [ECIES Swift Playground]: https://github.com/jedda/ecies-swift-playground
package main

import (
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"github.com/jedda/ecies"
	"log"
)

func main() {
	// Firstly, let's import a private key from a Base64 representation.
	// This is the same private key used in the [ECIES Swift Playground] linked above, so you can easily play around with
	// portable cross-platform encryption and decryption, but you can of course create your own keypair or use another
	// public key for encryption (such as one from a Secure Enclave on an Apple device).
	privateKey64 := "MHcCAQEEIE8vNIElmwxSR+Zhl5NooE+FEupEgFbPbn0q3hMIbd2BoAoGCCqGSM49AwEHoUQDQgAE7qMGCWG0L7HYAptVhIbLyx3cFzhd5EXZ09MpVpZmBGS7yCId5WQYKtmy3gTC245ivlEZ759ZPFgstYMgQoZrsg=="
	privateDecodedKey, err := base64.StdEncoding.DecodeString(privateKey64)
	if err != nil {
		log.Fatal(err)
	}
	// Now we parse the key into an ecdsa.PrivateKey and then into an ecdh.PrivateKey
	privateECKey, err := x509.ParseECPrivateKey(privateDecodedKey)
	if err != nil {
		log.Fatal(err)
	}
	privateECDHKey, err := privateECKey.ECDH()
	if err != nil {
		log.Fatal(err)
	}
	// Now, lets perform an encryption with the following parameters:
	publicKey := privateECDHKey.PublicKey() // our public key is the public key from our private
	plaintextMessage := []byte("Hello!")    // our plaintext is the string "Hello!"
	hashingAlgorithm := sha512.New384()     // SHA-384 as the hashing algorithm
	variableIV := true                      // use a variable IV/nonce derived from the KDF key
	additionalData := ([]byte)(nil)         // don't use any additional data for authentication
	// This is equivalent to kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA384AESGCM
	// (.eciesEncryptionCofactorVariableIVX963SHA384AESGCM) using Apple SecKeyAlgorithm
	// and SecKeyCreateEncryptedData()
	ciphertext, err := ecies.EncryptECIESX963AESGCM(hashingAlgorithm, variableIV, publicKey, plaintextMessage, additionalData)
	if err != nil {
		log.Fatal(err)
	}
	// Print our ciphertext as Base64. You can of course use the portable Base64 string to decrypt this data with the ECIES Companion Swift Playground
	fmt.Println("Ciphertext Base64:\n", base64.StdEncoding.EncodeToString(ciphertext))
	// Now let's decrypt the ciphertext back into plaintext using our private key.
	plaintext, err := ecies.DecryptECIESX963AESGCM(hashingAlgorithm, variableIV, privateECDHKey, ciphertext, nil)
	if err != nil {
		log.Fatal(err)
	}
	// And finally, we print our original plaintext message.
	fmt.Println("Plaintext:\n", string(plaintext[:]))
}
