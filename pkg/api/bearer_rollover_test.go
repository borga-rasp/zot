package api_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	. "github.com/smartystreets/goconvey/convey"
	"zotregistry.dev/zot/v2/pkg/api"
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/log"
)

func TestBearerKeyRollover(t *testing.T) {
	Convey("Zero-Downtime Key Rollover Multi-PEM Verification", t, func() {
		// 1. Generate Key-A and Key-B
		keyA, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		So(err, ShouldBeNil)
		keyB, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		So(err, ShouldBeNil)
		keyC, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader) // Untrusted key
		So(err, ShouldBeNil)

		// 2. Encode public keys into a single multi-PEM bundle
		pubKeyADER, err := x509.MarshalPKIXPublicKey(&keyA.PublicKey)
		So(err, ShouldBeNil)
		pubKeyBDER, err := x509.MarshalPKIXPublicKey(&keyB.PublicKey)
		So(err, ShouldBeNil)

		pemA := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyADER})
		pemB := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBDER})
		multiPEMBundle := append(pemA, pemB...)

		// 3. Write bundle to temp file
		tempDir := t.TempDir()
		bundlePath := filepath.Join(tempDir, "public.pem")
		err = os.WriteFile(bundlePath, multiPEMBundle, 0600)
		So(err, ShouldBeNil)

		// 4. Initialize Zot Bearer Auth with the multi-key bundle
		authConfig := &config.AuthConfig{
			Bearer: &config.BearerConfig{
				Realm:   "https://build.borgasec.app/v2/token",
				Service: "registry.borgasec.app",
				Cert:    bundlePath,
			},
		}
		logger := log.NewTestLogger()
		bearerAuth := api.NewBearerAuth(authConfig, logger)
		So(bearerAuth, ShouldNotBeNil)

		kidA := api.ComputePublicKeyID(&keyA.PublicKey)
		kidB := api.ComputePublicKeyID(&keyB.PublicKey)
		So(kidA, ShouldNotBeEmpty)
		So(kidB, ShouldNotBeEmpty)
		So(kidA, ShouldNotEqual, kidB)

		reqAccess := &api.ResourceAction{
			Name:   "borga-rasp/backend",
			Type:   "repository",
			Action: "pull",
		}

		claims := api.ClaimsWithAccess{
			Access: []api.ResourceAccess{
				{
					Name:    "borga-rasp/backend",
					Type:    "repository",
					Actions: []string{"pull"},
				},
			},
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				Issuer:    "borga-build-server",
				Audience:  []string{"registry.borgasec.app"},
			},
		}

		Convey("Token signed with Key-A (with kidA) verifies successfully", func() {
			tokenObj := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
			tokenObj.Header["kid"] = kidA
			signedA, err := tokenObj.SignedString(keyA)
			So(err, ShouldBeNil)

			authorizer := api.NewBearerAuthorizer(authConfig.Bearer.Realm, authConfig.Bearer.Service, func(ctx context.Context, token *jwt.Token) (any, error) {
				keyring, kErr := api.LoadKeyringFromFile(bundlePath)
				So(kErr, ShouldBeNil)
				var kid string
				if k, ok := token.Header["kid"].(string); ok {
					kid = k
				}
				return keyring.GetKey(kid), nil
			})

			err = authorizer.Authorize(context.Background(), "Bearer "+signedA, reqAccess)
			So(err, ShouldBeNil)
		})

		Convey("Token signed with Key-B (with kidB) verifies successfully", func() {
			tokenObj := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
			tokenObj.Header["kid"] = kidB
			signedB, err := tokenObj.SignedString(keyB)
			So(err, ShouldBeNil)

			authorizer := api.NewBearerAuthorizer(authConfig.Bearer.Realm, authConfig.Bearer.Service, func(ctx context.Context, token *jwt.Token) (any, error) {
				keyring, kErr := api.LoadKeyringFromFile(bundlePath)
				So(kErr, ShouldBeNil)
				var kid string
				if k, ok := token.Header["kid"].(string); ok {
					kid = k
				}
				return keyring.GetKey(kid), nil
			})

			err = authorizer.Authorize(context.Background(), "Bearer "+signedB, reqAccess)
			So(err, ShouldBeNil)
		})

		Convey("Token signed with untrusted Key-C fails verification", func() {
			tokenObj := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
			tokenObj.Header["kid"] = "untrusted-kid"
			signedC, err := tokenObj.SignedString(keyC)
			So(err, ShouldBeNil)

			authorizer := api.NewBearerAuthorizer(authConfig.Bearer.Realm, authConfig.Bearer.Service, func(ctx context.Context, token *jwt.Token) (any, error) {
				keyring, kErr := api.LoadKeyringFromFile(bundlePath)
				So(kErr, ShouldBeNil)
				var kid string
				if k, ok := token.Header["kid"].(string); ok {
					kid = k
				}
				return keyring.GetKey(kid), nil
			})

			err = authorizer.Authorize(context.Background(), "Bearer "+signedC, reqAccess)
			So(err, ShouldNotBeNil)
		})
	})
}
