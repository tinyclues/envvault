package main

import (
	"fmt"
	"os"
	"strings"
)

type Environment interface {
	List() []string
}

type OsEnvironment struct{}

func NewOsEnvironment() Environment {
	return &OsEnvironment{}
}

func (e OsEnvironment) List() []string {
	return os.Environ()
}

func GetEnvVarsWithPaths(env Environment) EnvVars {
	envVars := NewEmptyEnvVars()
	for _, envVar := range env.List() {
		elements := strings.SplitN(envVar, "=", 2)
		name := elements[0]
		value := elements[1]
		if !strings.HasSuffix(name, "_VAULT") {
			continue
		}
		nameWithoutSuffix := strings.TrimSuffix(name, "_VAULT")

		envVars[nameWithoutSuffix] = value
	}
	return envVars
}

type EnvVars map[string]string

func NewEmptyEnvVars() EnvVars {
	return make(EnvVars)
}

func (e EnvVars) ExportStrings() []string {
	envStrings := make([]string, len(e))
	index := 0
	for name, value := range e {
		envStrings[index] = fmt.Sprintf(`export "%s"="%s"`, name, value)
		index++
	}
	return envStrings
}
