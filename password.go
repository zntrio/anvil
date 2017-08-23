package anvil

// Seal a public key matching the principal / password credentials
func Seal(principal, password string) (string, error) {
	// Derive password to generate the key pair
	pub, _, err := derivePassword([]byte(principal), []byte(password))
	if err != nil {
		return "", err
	}

	// Encode public key to OKP
	return toOKP(pub), nil
}
