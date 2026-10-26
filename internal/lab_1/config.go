package lab_1

import (
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	Keys *EncryptionKeys
}

type EncryptionKeys struct {
	Substitution     string
	Vigenere         string
	BlockPermutation string
	Columnar         string
	Homophonic       string
}

func Configure() *Config {
	_ = godotenv.Load()

	return &Config{
		Keys: &EncryptionKeys{
			Substitution:     os.Getenv("LAB1_SUBSTITUTION_KEY"),
			Vigenere:         os.Getenv("LAB1_VIGENERE_KEY"),
			BlockPermutation: os.Getenv("LAB1_BLOCK_PERMUTATION_KEY"),
			Columnar:         os.Getenv("LAB1_COLUMNAR_KEY"),
			Homophonic:       os.Getenv("LAB1_HOMOPHONIC_SEED"),
		},
	}
}
