package main

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

type FakeEnv struct {
	environment []string
}

func NewFakeEnv(environment []string) Environment {
	return &FakeEnv{environment}
}

func (e FakeEnv) List() []string {
	return e.environment
}

func TestGetEnvVarsWithPaths_returns_envvars_with_suffix(t *testing.T) {
	// Given
	env := NewFakeEnv([]string{
		"MY_VAR_VAULT=my/secret/path",
		"MY_OTHER_VAR_VAULT=my/other/secret/path",
	})
	// When
	envVars := GetEnvVarsWithPaths(env)
	// Then
	expected := NewEmptyEnvVars()
	expected["MY_VAR"] = "my/secret/path"
	expected["MY_OTHER_VAR"] = "my/other/secret/path"
	assert.Equal(t,
		expected,
		envVars,
	)
}

func TestGetEnvVarsWithPaths_does_not_return_envvars_without_suffix(t *testing.T) {
	// Given
	env := NewFakeEnv([]string{
		"SOMETHING=someValue",
	})
	// When
	envVars := GetEnvVarsWithPaths(env)
	// Then
	assert.Equal(t,
		NewEmptyEnvVars(),
		envVars,
	)
}

func TestGetEnvVarsWithPaths_can_split_complex_envvars(t *testing.T) {
	// Given
	env := NewFakeEnv([]string{
		"MY_VAR_VAULT=my/secret/path=something",
	})
	// When
	envVars := GetEnvVarsWithPaths(env)
	// Then
	expected := NewEmptyEnvVars()
	expected["MY_VAR"] = "my/secret/path=something"
	assert.Equal(t,
		expected,
		envVars,
	)
}

func TestGetEnvVarsWithPaths_ExportStrings_returns_strings(t *testing.T) {
	// Given
	env := NewEmptyEnvVars()
	env["ABC"] = "def"
	// When
	result := env.ExportStrings()
	// Then
	assert.Equal(t,
		[]string{`export "ABC"="def"`},
		result,
	)
}
