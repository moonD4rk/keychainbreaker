package keychainbreaker

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEntropyPath(t *testing.T) {
	kc := openTestKeychain(t)
	assert.Equal(t, "/var/db/SystemKeys/FC143C45CCE245F3E54FBB39141A894E2870DD85", kc.EntropyPath())
}

const sampleEntropyPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<data>
AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=
</data>
</plist>`

func TestDecodeEntropy(t *testing.T) {
	secret, err := DecodeEntropy([]byte(sampleEntropyPlist))
	require.NoError(t, err)
	require.Len(t, secret, 32)
	for i := range secret {
		assert.Equal(t, byte(i), secret[i])
	}
}

func TestDecodeEntropyRejectsBadInput(t *testing.T) {
	tests := map[string]string{
		"not a plist": "just text",
		"no data":     `<plist version="1.0"><dict/></plist>`,
		"bad base64":  `<plist version="1.0"><data>!!!!</data></plist>`,
	}
	for name, in := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := DecodeEntropy([]byte(in))
			assert.Error(t, err)
		})
	}
}
