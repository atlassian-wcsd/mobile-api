package appleauth

import (
	"testing"
)

// TestJwkToRSAPublicKey tests the primary implementation using jwx library
func TestJwkToRSAPublicKey(t *testing.T) {
	service := &AppleAuthService{}

	// Real Apple JWK data from https://appleid.apple.com/auth/keys
	// This is a sample key structure that matches Apple's format
	testJWK := &AppleJWK{
		Kty: "RSA",
		Kid: "86D88Kf",
		Use: "sig",
		Alg: "RS256",
		// These are example base64url encoded values for testing
		// N is the modulus, E is the exponent
		N: "iGaLqP6y-SJCCBq5Hv6pGDbG_SQ11MNjH7rWHcCFYz4hGwHC4lcSurTlV8u3avoVNM8jXevG1Iu1SY11qInqUvjJur--hghr1b56OPJu6H1iKulSxGjEIyDP6c5BdE1uwprYyr4IO9th8fOwCPygjLFrh44XEGbDIFeImwvBAGOhmMB2AD1n1KviyNsH0bEB7phQtiLk-ILjv1bORSRl8AK677-1T8isGfHKXGZ_ZGtStDe7Lu0Ihp8zoUt59kx2o9uWpROkzF56ypresiIl4WprClRCjz8x6cPZXU2qNWhu71TQvUFwvIvbkE1oYaJMb0jcOTmBRZA2QuYw-zHLwQ",
		E: "AQAB",
	}

	t.Run("Valid JWK conversion", func(t *testing.T) {
		rsaKey, err := service.jwkToRSAPublicKey(testJWK)
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}

		if rsaKey == nil {
			t.Fatal("Expected RSA key, got nil")
		}

		// Verify it's a valid RSA public key
		if rsaKey.N == nil {
			t.Error("RSA key modulus (N) is nil")
		}

		if rsaKey.E == 0 {
			t.Error("RSA key exponent (E) is 0")
		}

		// Common RSA exponent is 65537 (AQAB in base64url)
		if rsaKey.E != 65537 {
			t.Errorf("Expected exponent 65537, got %d", rsaKey.E)
		}
	})

	t.Run("Invalid modulus", func(t *testing.T) {
		invalidJWK := &AppleJWK{
			Kty: "RSA",
			Kid: "test",
			Use: "sig",
			Alg: "RS256",
			N:   "invalid!!!base64",
			E:   "AQAB",
		}

		_, err := service.jwkToRSAPublicKey(invalidJWK)
		if err == nil {
			t.Error("Expected error for invalid modulus, got nil")
		}
	})

	t.Run("Invalid exponent", func(t *testing.T) {
		invalidJWK := &AppleJWK{
			Kty: "RSA",
			Kid: "test",
			Use: "sig",
			Alg: "RS256",
			N:   "iGaLqP6y-SJCCBq5Hv6pGDbG_SQ11MNjH7rWHcCFYz4hGwHC4lcSurTlV8u3avoVNM8jXevG1Iu1SY11qInqUvjJur--hghr1b56OPJu6H1iKulSxGjEIyDP6c5BdE1uwprYyr4IO9th8fOwCPygjLFrh44XEGbDIFeImwvBAGOhmMB2AD1n1KviyNsH0bEB7phQtiLk-ILjv1bORSRl8AK677-1T8isGfHKXGZ_ZGtStDe7Lu0Ihp8zoUt59kx2o9uWpROkzF56ypresiIl4WprClRCjz8x6cPZXU2qNWhu71TQvUFwvIvbkE1oYaJMb0jcOTmBRZA2QuYw-zHLwQ",
			E:   "invalid!!!",
		}

		_, err := service.jwkToRSAPublicKey(invalidJWK)
		if err == nil {
			t.Error("Expected error for invalid exponent, got nil")
		}
	})
}

// TestJwkToRSAPublicKeyStdLib tests the standard library implementation
func TestJwkToRSAPublicKeyStdLib(t *testing.T) {
	service := &AppleAuthService{}

	testJWK := &AppleJWK{
		Kty: "RSA",
		Kid: "86D88Kf",
		Use: "sig",
		Alg: "RS256",
		N:   "iGaLqP6y-SJCCBq5Hv6pGDbG_SQ11MNjH7rWHcCFYz4hGwHC4lcSurTlV8u3avoVNM8jXevG1Iu1SY11qInqUvjJur--hghr1b56OPJu6H1iKulSxGjEIyDP6c5BdE1uwprYyr4IO9th8fOwCPygjLFrh44XEGbDIFeImwvBAGOhmMB2AD1n1KviyNsH0bEB7phQtiLk-ILjv1bORSRl8AK677-1T8isGfHKXGZ_ZGtStDe7Lu0Ihp8zoUt59kx2o9uWpROkzF56ypresiIl4WprClRCjz8x6cPZXU2qNWhu71TQvUFwvIvbkE1oYaJMb0jcOTmBRZA2QuYw-zHLwQ",
		E:   "AQAB",
	}

	t.Run("Valid JWK conversion with stdlib", func(t *testing.T) {
		rsaKey, err := service.jwkToRSAPublicKeyStdLib(testJWK)
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}

		if rsaKey == nil {
			t.Fatal("Expected RSA key, got nil")
		}

		if rsaKey.N == nil {
			t.Error("RSA key modulus (N) is nil")
		}

		if rsaKey.E == 0 {
			t.Error("RSA key exponent (E) is 0")
		}

		if rsaKey.E != 65537 {
			t.Errorf("Expected exponent 65537, got %d", rsaKey.E)
		}
	})

	t.Run("Invalid modulus with stdlib", func(t *testing.T) {
		invalidJWK := &AppleJWK{
			Kty: "RSA",
			Kid: "test",
			Use: "sig",
			Alg: "RS256",
			N:   "invalid!!!base64",
			E:   "AQAB",
		}

		_, err := service.jwkToRSAPublicKeyStdLib(invalidJWK)
		if err == nil {
			t.Error("Expected error for invalid modulus, got nil")
		}
	})

	t.Run("Invalid exponent with stdlib", func(t *testing.T) {
		invalidJWK := &AppleJWK{
			Kty: "RSA",
			Kid: "test",
			Use: "sig",
			Alg: "RS256",
			N:   "iGaLqP6y-SJCCBq5Hv6pGDbG_SQ11MNjH7rWHcCFYz4hGwHC4lcSurTlV8u3avoVNM8jXevG1Iu1SY11qInqUvjJur--hghr1b56OPJu6H1iKulSxGjEIyDP6c5BdE1uwprYyr4IO9th8fOwCPygjLFrh44XEGbDIFeImwvBAGOhmMB2AD1n1KviyNsH0bEB7phQtiLk-ILjv1bORSRl8AK677-1T8isGfHKXGZ_ZGtStDe7Lu0Ihp8zoUt59kx2o9uWpROkzF56ypresiIl4WprClRCjz8x6cPZXU2qNWhu71TQvUFwvIvbkE1oYaJMb0jcOTmBRZA2QuYw-zHLwQ",
			E:   "invalid!!!",
		}

		_, err := service.jwkToRSAPublicKeyStdLib(invalidJWK)
		if err == nil {
			t.Error("Expected error for invalid exponent, got nil")
		}
	})

	t.Run("Exponent too large", func(t *testing.T) {
		invalidJWK := &AppleJWK{
			Kty: "RSA",
			Kid: "test",
			Use: "sig",
			Alg: "RS256",
			N:   "iGaLqP6y-SJCCBq5Hv6pGDbG_SQ11MNjH7rWHcCFYz4hGwHC4lcSurTlV8u3avoVNM8jXevG1Iu1SY11qInqUvjJur--hghr1b56OPJu6H1iKulSxGjEIyDP6c5BdE1uwprYyr4IO9th8fOwCPygjLFrh44XEGbDIFeImwvBAGOhmMB2AD1n1KviyNsH0bEB7phQtiLk-ILjv1bORSRl8AK677-1T8isGfHKXGZ_ZGtStDe7Lu0Ihp8zoUt59kx2o9uWpROkzF56ypresiIl4WprClRCjz8x6cPZXU2qNWhu71TQvUFwvIvbkE1oYaJMb0jcOTmBRZA2QuYw-zHLwQ",
			// 5 bytes - too large for int
			E: "AQABAQAB",
		}

		_, err := service.jwkToRSAPublicKeyStdLib(invalidJWK)
		if err == nil {
			t.Error("Expected error for exponent too large, got nil")
		}
	})
}

// TestBothImplementationsProduceSameKey verifies both implementations produce identical results
func TestBothImplementationsProduceSameKey(t *testing.T) {
	service := &AppleAuthService{}

	testJWK := &AppleJWK{
		Kty: "RSA",
		Kid: "86D88Kf",
		Use: "sig",
		Alg: "RS256",
		N:   "iGaLqP6y-SJCCBq5Hv6pGDbG_SQ11MNjH7rWHcCFYz4hGwHC4lcSurTlV8u3avoVNM8jXevG1Iu1SY11qInqUvjJur--hghr1b56OPJu6H1iKulSxGjEIyDP6c5BdE1uwprYyr4IO9th8fOwCPygjLFrh44XEGbDIFeImwvBAGOhmMB2AD1n1KviyNsH0bEB7phQtiLk-ILjv1bORSRl8AK677-1T8isGfHKXGZ_ZGtStDe7Lu0Ihp8zoUt59kx2o9uWpROkzF56ypresiIl4WprClRCjz8x6cPZXU2qNWhu71TQvUFwvIvbkE1oYaJMb0jcOTmBRZA2QuYw-zHLwQ",
		E:   "AQAB",
	}

	rsaKey1, err1 := service.jwkToRSAPublicKey(testJWK)
	if err1 != nil {
		t.Fatalf("jwkToRSAPublicKey failed: %v", err1)
	}

	rsaKey2, err2 := service.jwkToRSAPublicKeyStdLib(testJWK)
	if err2 != nil {
		t.Fatalf("jwkToRSAPublicKeyStdLib failed: %v", err2)
	}

	// Compare the keys
	if rsaKey1.E != rsaKey2.E {
		t.Errorf("Exponents don't match: %d vs %d", rsaKey1.E, rsaKey2.E)
	}

	if rsaKey1.N.Cmp(rsaKey2.N) != 0 {
		t.Error("Modulus values don't match")
	}
}

// BenchmarkJwkToRSAPublicKey benchmarks the jwx library implementation
func BenchmarkJwkToRSAPublicKey(b *testing.B) {
	service := &AppleAuthService{}
	testJWK := &AppleJWK{
		Kty: "RSA",
		Kid: "86D88Kf",
		Use: "sig",
		Alg: "RS256",
		N:   "iGaLqP6y-SJCCBq5Hv6pGDbG_SQ11MNjH7rWHcCFYz4hGwHC4lcSurTlV8u3avoVNM8jXevG1Iu1SY11qInqUvjJur--hghr1b56OPJu6H1iKulSxGjEIyDP6c5BdE1uwprYyr4IO9th8fOwCPygjLFrh44XEGbDIFeImwvBAGOhmMB2AD1n1KviyNsH0bEB7phQtiLk-ILjv1bORSRl8AK677-1T8isGfHKXGZ_ZGtStDe7Lu0Ihp8zoUt59kx2o9uWpROkzF56ypresiIl4WprClRCjz8x6cPZXU2qNWhu71TQvUFwvIvbkE1oYaJMb0jcOTmBRZA2QuYw-zHLwQ",
		E:   "AQAB",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = service.jwkToRSAPublicKey(testJWK)
	}
}

// BenchmarkJwkToRSAPublicKeyStdLib benchmarks the standard library implementation
func BenchmarkJwkToRSAPublicKeyStdLib(b *testing.B) {
	service := &AppleAuthService{}
	testJWK := &AppleJWK{
		Kty: "RSA",
		Kid: "86D88Kf",
		Use: "sig",
		Alg: "RS256",
		N:   "iGaLqP6y-SJCCBq5Hv6pGDbG_SQ11MNjH7rWHcCFYz4hGwHC4lcSurTlV8u3avoVNM8jXevG1Iu1SY11qInqUvjJur--hghr1b56OPJu6H1iKulSxGjEIyDP6c5BdE1uwprYyr4IO9th8fOwCPygjLFrh44XEGbDIFeImwvBAGOhmMB2AD1n1KviyNsH0bEB7phQtiLk-ILjv1bORSRl8AK677-1T8isGfHKXGZ_ZGtStDe7Lu0Ihp8zoUt59kx2o9uWpROkzF56ypresiIl4WprClRCjz8x6cPZXU2qNWhu71TQvUFwvIvbkE1oYaJMb0jcOTmBRZA2QuYw-zHLwQ",
		E:   "AQAB",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = service.jwkToRSAPublicKeyStdLib(testJWK)
	}
}
