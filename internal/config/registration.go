package config

import (
	"errors"
	"fmt"
	"strings"

	"gopkg.in/ini.v1"
)

// SaveHawkbitRegistration saves and enables a successfully registered gateway profile.
// Other settings and library-parsed comments are retained, without using any
// existing value as registration input. The library may normalize formatting.
func SaveHawkbitRegistration(path string, profile HawkbitConfig) error {
	fields, err := registrationFields(profile)
	if err != nil {
		return err
	}
	return editINIFile(path, func(file *ini.File) (bool, error) {
		section := file.Section("hawkbit")
		for _, field := range fields {
			section.Key(field.key).SetValue(field.value)
		}
		return true, nil
	})
}

type registrationField struct{ key, value string }

func registrationFields(profile HawkbitConfig) ([]registrationField, error) {
	if profile.TokenType != "" && profile.TokenType != "gateway" {
		return nil, errors.New("registration requires gateway token authentication")
	}
	fields := []registrationField{
		{"server_url", profile.ServerURL}, {"tenant", profile.Tenant},
		{"controller_id", profile.ControllerID}, {"token", profile.Token},
		{"token_type", "gateway"}, {"enabled", "true"},
	}
	validated := defaults()
	for _, field := range fields {
		if field.value == "" || strings.ContainsAny(field.value, "\x00\r\n") || assign(&validated, "hawkbit."+field.key, field.value) != nil {
			// Never include a supplied value or a parser error containing it.
			return nil, fmt.Errorf("invalid hawkBit registration %s", field.key)
		}
	}
	fields[0].value = validated.Hawkbit.ServerURL
	return fields, nil
}
