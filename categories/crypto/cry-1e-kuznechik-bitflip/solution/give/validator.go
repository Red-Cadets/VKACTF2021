package validator

import (
	b64 "encoding/base64"
	"crypto/cipher"
	"fmt"
	"os"
	"errors"
	kuz "github.com/ddulesov/gogost/gost3412128"
)

func check(e error) {
    if e != nil {
        panic(e)
    }
}

func Unpad(src []byte) ([]byte, error) {
    length := len(src)
    unpadding := int(src[length-1])

    if unpadding > length {
        return nil, errors.New("unpad error")
    }

    return src[:(length - unpadding)], nil
}

type SecureCipher struct{}

func (cip *SecureCipher) DecryptData(ct string) (string, error) {
	f, err := os.Open("cryptor/key")
    check(err)
	CipherKey := make([]byte, 32)
	
	f.Read(CipherKey)
	block := kuz.NewCipher(CipherKey)
	ciphertext, err := b64.StdEncoding.DecodeString(ct)

	if err != nil {
		return "", errors.New("Ошибка декодирования")
	}
	if len(ciphertext) < kuz.BlockSize {
		return "", errors.New("Код-приглашение слишком короткий")
	}

	iv := ciphertext[:kuz.BlockSize]
	ciphertext = ciphertext[kuz.BlockSize:]

	if len(ciphertext)%kuz.BlockSize != 0 {
		return "", errors.New("Ошибка обработки")
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)
	ciphertext, err = Unpad( ciphertext )
	if err != nil {
		return "", errors.New("Ошибка декодирования")
	}
	return fmt.Sprintf("%s",ciphertext ), nil
	
}

func Validate(name string, code string) (string, error) {
	c := SecureCipher{}
	dec, err := c.DecryptData(code)
	if err != nil {
		return "", err
	}

	if name != dec{
		return "", errors.New("Неверный код!")
	}
	
	// Accepted!
	return fmt.Sprintf("%v", dec), nil // welcome!
}