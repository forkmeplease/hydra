// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package x

import (
	"github.com/ory/fosite/storage"
)

func FositeStore() *storage.MemoryStore {
	return storage.NewMemoryStore()
}
