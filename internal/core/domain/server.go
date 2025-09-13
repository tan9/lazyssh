// Copyright 2025.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package domain

import "time"

type Server struct {
	Alias         string
	Aliases       []string
	Host          string
	User          string
	Port          int
	IdentityFiles []string
	Tags          []string
	LastSeen      time.Time
	PinnedAt      time.Time
	SSHCount      int

	// Additional SSH config fields
	// Connection and proxy settings
	ProxyJump            string
	ProxyCommand         string
	RemoteCommand        string
	RequestTTY           string
	SessionType          string // none, subsystem, default (OpenSSH 8.7+)
	ConnectTimeout       string
	ConnectionAttempts   string
	BindAddress          string
	BindInterface        string
	AddressFamily        string // any, inet, inet6
	ExitOnForwardFailure string // yes, no

	// Port forwarding settings
	LocalForward        []string
	RemoteForward       []string
	DynamicForward      []string
	ClearAllForwardings string // yes, no

	// Authentication and key management
	// Public key
	PubkeyAuthentication        string
	PubkeyAcceptedAlgorithms    string
	HostbasedAcceptedAlgorithms string
	IdentitiesOnly              string
	// SSH Agent
	AddKeysToAgent string
	IdentityAgent  string
	// Password & Interactive
	PasswordAuthentication       string
	KbdInteractiveAuthentication string // yes, no
	NumberOfPasswordPrompts      string
	// Advanced
	PreferredAuthentications string

	// Agent and X11 forwarding
	ForwardAgent      string
	ForwardX11        string
	ForwardX11Trusted string

	// Connection multiplexing
	ControlMaster  string
	ControlPath    string
	ControlPersist string

	// Connection reliability settings
	ServerAliveInterval string
	ServerAliveCountMax string
	Compression         string
	TCPKeepAlive        string

	// Security and cryptography settings
	StrictHostKeyChecking string
	UserKnownHostsFile    string
	HostKeyAlgorithms     string
	MACs                  string
	Ciphers               string
	KexAlgorithms         string

	// Command execution
	LocalCommand       string
	PermitLocalCommand string

	// Environment settings
	SendEnv []string
	SetEnv  []string

	// Debugging settings
	LogLevel  string
	BatchMode string
}
