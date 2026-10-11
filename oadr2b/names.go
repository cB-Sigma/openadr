// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package oadr2b

// Response codes, service names and paths of the 2.0b profile.

// Application response codes (2.0b profile section 8.7).
const (
	CodeOK             = "200"
	CodeOutOfSequence  = "450"
	CodeNotAllowed     = "451"
	CodeInvalidID      = "452"
	CodeNotRecognized  = "453"
	CodeInvalidData    = "454"
	CodeComplianceErr  = "459"
	CodeSignalNotSupp  = "460"
	CodeReportNotSupp  = "461"
	CodeTargetMismatch = "462"
	CodeNotRegistered  = "463"
	CodeDeploymentErr  = "469"
	// CodeBadSignature answers a message refused under xmlSignature
	// "require" (our choice: the not registered or not authorised code).
	CodeBadSignature = CodeNotRegistered
)

// Profile and transport names this VTN offers.
const (
	ProfileName   = Profile20b
	TransportName = "simpleHttp"
)

// Service endpoints under {prefix}/OpenADR2/Simple/2.0b/.
const (
	ServiceRegisterParty = "EiRegisterParty"
	ServiceEvent         = "EiEvent"
	ServiceReport        = "EiReport"
	ServiceOpt           = "EiOpt"
	ServicePoll          = "OadrPoll"
	// PathBase is the simple-HTTP path before the service name.
	PathBase = "/OpenADR2/Simple/2.0b/"
)

// TransportXMPP is the oadrTransportName of XMPP.
const TransportXMPP = "xmpp"
