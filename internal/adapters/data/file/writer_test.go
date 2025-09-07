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

package file

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Adembc/lazyssh/internal/core/domain"
)

func TestSSHConfigWriter_toRelativePath(t *testing.T) {
	w := &SSHConfigWriter{}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("Failed to get home directory: %v", err)
	}

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "already relative path",
			input:    "~/.ssh/id_rsa",
			expected: "~/.ssh/id_rsa",
		},
		{
			name:     "absolute path under home",
			input:    filepath.Join(home, ".ssh", "id_rsa"),
			expected: "~/.ssh/id_rsa",
		},
		{
			name:     "absolute path under home nested",
			input:    filepath.Join(home, ".ssh", "keys", "id_ed25519"),
			expected: "~/.ssh/keys/id_ed25519",
		},
		{
			name:     "absolute path outside home",
			input:    "/etc/ssh/ssh_host_rsa_key",
			expected: "/etc/ssh/ssh_host_rsa_key",
		},
		{
			name:     "home directory only",
			input:    home,
			expected: "~",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := w.toRelativePath(tt.input)
			if result != tt.expected {
				t.Errorf("toRelativePath(%q) = %q, expected %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestSSHConfigWriter_Write_WithRelativePaths(t *testing.T) {
	w := &SSHConfigWriter{}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("Failed to get home directory: %v", err)
	}

	servers := []domain.Server{
		{
			Alias: "test-server",
			Host:  "192.168.1.100",
			User:  "testuser",
			Port:  22,
			Key:   filepath.Join(home, ".ssh", "id_rsa"),
		},
		{
			Alias: "already-relative",
			Host:  "192.168.1.101",
			User:  "user2",
			Port:  2222,
			Key:   "~/.ssh/id_ed25519",
		},
		{
			Alias: "absolute-outside-home",
			Host:  "192.168.1.102",
			User:  "root",
			Port:  22,
			Key:   "/etc/ssh/ssh_host_key",
		},
	}

	var buf bytes.Buffer
	err = w.Write(&buf, servers)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	output := buf.String()

	// Verify first server's IdentityFile uses relative path
	if !strings.Contains(output, "IdentityFile ~/.ssh/id_rsa") {
		t.Errorf("Expected to find 'IdentityFile ~/.ssh/id_rsa', but got:\n%s", output)
	}

	// Verify second server keeps relative path
	if !strings.Contains(output, "IdentityFile ~/.ssh/id_ed25519") {
		t.Errorf("Expected to find 'IdentityFile ~/.ssh/id_ed25519', but got:\n%s", output)
	}

	// Verify third server keeps absolute path (not under home)
	if !strings.Contains(output, "IdentityFile /etc/ssh/ssh_host_key") {
		t.Errorf("Expected to find 'IdentityFile /etc/ssh/ssh_host_key', but got:\n%s", output)
	}
}
