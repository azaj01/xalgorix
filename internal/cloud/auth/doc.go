// Package auth implements first-party authentication for the Xalgorix
// Cloud_Platform: sessions, OAuth (Google + GitHub), magic links, TOTP MFA,
// password policy with HIBP k-anonymity, account lockout, password reset,
// and Enterprise SAML/OIDC SSO.
//
// This package corresponds to the design.md section
// "Components and Interfaces → internal/cloud/auth". Concrete files
// (password.go, hibp.go, session.go, oauth.go, magiclink.go, mfa.go,
// lockout.go, sso.go) are added by Phase 2 tasks 2.1 through 2.12.
//
// Created by task 0.1 — Bootstrap Go module layout.
// Requirements: 1.1, 1.9
package auth
