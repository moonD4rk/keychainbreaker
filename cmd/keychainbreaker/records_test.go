package main

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/moond4rk/keychainbreaker"
)

func TestNewPasswordText(t *testing.T) {
	assert.Equal(t, passwordText{
		Password:       "password#123",
		HexPassword:    "70617373776f726423313233",
		Base64Password: "cGFzc3dvcmQjMTIz",
	}, newPasswordText([]byte("password#123")))
	assert.Equal(t, passwordText{}, newPasswordText(nil))
}

func TestGenericPasswordJSON(t *testing.T) {
	created := time.Date(2026, 3, 27, 15, 51, 0, 0, time.UTC)
	data, err := json.Marshal(newGenericPassword(&keychainbreaker.GenericPassword{
		Service:  "moond4rk.com",
		Account:  "admin",
		Password: []byte{0xff, 'a'},
		Created:  created,
	}))
	require.NoError(t, err)
	assert.JSONEq(t, `{
		"service": "moond4rk.com",
		"account": "admin",
		"password": "�a",
		"hex_password": "ff61",
		"base64_password": "/2E=",
		"created_at": "2026-03-27T15:51:00Z"
	}`, string(data))
}

func TestLockedRecordsOmitSecretsAndMissingTimes(t *testing.T) {
	data, err := json.Marshal(dump{
		InternetPasswords: []internetPassword{newInternetPassword(&keychainbreaker.InternetPassword{Server: "moond4rk.com", Port: 443})},
		PrivateKeys:       []privateKey{newPrivateKey(&keychainbreaker.PrivateKey{PrintName: "key"})},
	})
	require.NoError(t, err)
	assert.JSONEq(t, `{
		"internet_passwords": [{"server": "moond4rk.com", "port": 443}],
		"private_keys": [{"print_name": "key"}]
	}`, string(data))
}

func TestCertificateJSON(t *testing.T) {
	data, err := json.Marshal(newCertificate(&keychainbreaker.Certificate{
		Data:      []byte{0x30, 0x82},
		PrintName: "cert",
		Subject:   []byte{0x01},
		Serial:    []byte{0x02},
	}))
	require.NoError(t, err)
	assert.JSONEq(t, `{
		"data_hex": "3082",
		"data_base64": "MII=",
		"print_name": "cert",
		"subject_hex": "01",
		"serial_hex": "02"
	}`, string(data))
}
