package patatt

import (
	"errors"
)

var (
	ConfigurationErr = errors.New("configuration error")
	SigningErr       = errors.New("signing error")
	KeyErr           = errors.New("key error")
)

func Sign(m *Message, c Config) ([]byte, error) {
	err := m.Sign(c.Algo(), c.Keydata(), c.Identity, c.Selector)
	if err != nil {
		return nil, err
	}
	signed := m.Bytes()
	Debugf("--- SIGNED MESSAGE STARTS ---\n")
	Debugf(string(signed))
	return signed, nil
}
