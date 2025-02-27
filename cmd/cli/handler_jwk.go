// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	jose "gopkg.in/square/go-jose.v2"
)

func ToSDKFriendlyJSONWebKey(key interface{}, kid, use string) jose.JSONWebKey {
	var alg string

	if jwk, ok := key.(*jose.JSONWebKey); ok {
		key = jwk.Key
		if jwk.KeyID != "" {
			kid = jwk.KeyID
		}
		if jwk.Use != "" {
			use = jwk.Use
		}
		if jwk.Algorithm != "" {
			alg = jwk.Algorithm
		}
	}

	return jose.JSONWebKey{
		KeyID:     kid,
		Use:       use,
		Algorithm: alg,
		Key:       key,
	}
}
