package security

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/base64"
    "errors"
    "io"
)

// Encrypt encrypts the given plaintext using AES encryption.
func Encrypt(plaintext string, key string) (string, error) {
    block, err := aes.NewCipher([]byte(key))
    if err != nil {
        return "", err
    }

    ciphertext := make([]byte, aes.BlockSize+len(plaintext))
    iv := ciphertext[:aes.BlockSize]
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return "", err
    }

    stream := cipher.NewCFBEncrypter(block, iv)
    stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(plaintext))

    return base64.URLEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts the given ciphertext using AES decryption.
func Decrypt(ciphertext string, key string) (string, error) {
    ciphertextBytes, err := base64.URLEncoding.DecodeString(ciphertext)
    if err != nil {
        return "", err
    }

    block, err := aes.NewCipher([]byte(key))
    if err != nil {
        return "", err
    }

    if len(ciphertextBytes) < aes.BlockSize {
        return "", errors.New("ciphertext too short")
    }

    iv := ciphertextBytes[:aes.BlockSize]
    ciphertextBytes = ciphertextBytes[aes.BlockSize:]

    stream := cipher.NewCFBDecrypter(block, iv)
    stream.XORKeyStream(ciphertextBytes, ciphertextBytes)

    return string(ciphertextBytes), nil
}
