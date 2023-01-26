// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

//go:build !sqlite
// +build !sqlite

package driver

func (m *RegistrySQL) CanHandle(dsn string) bool {
	return m.alwaysCanHandle(dsn)
}
