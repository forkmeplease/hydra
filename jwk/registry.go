// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package jwk

import (
	"github.com/ory/hydra/driver/config"
	"github.com/ory/hydra/x"
)

type InternalRegistry interface {
	x.RegistryWriter
	x.RegistryLogger
	Registry
}

type Registry interface {
	config.Provider
	KeyManager() Manager
	SoftwareKeyManager() Manager
	KeyCipher() *AEAD
}
