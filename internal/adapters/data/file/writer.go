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
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Adembc/lazyssh/internal/core/domain"
)

type SSHConfigWriter struct{}

func (w *SSHConfigWriter) Write(writer io.Writer, servers []domain.Server) error {
	bufWriter := bufio.NewWriter(writer)
	defer func() {
		_ = bufWriter.Flush()
	}()

	if _, err := fmt.Fprintf(bufWriter, "%s\n\n", ManagedByComment); err != nil {
		return err
	}

	for i, server := range servers {
		if i > 0 {
			if _, err := bufWriter.WriteString("\n"); err != nil {
				return err
			}
		}
		if err := w.writeServer(bufWriter, server); err != nil {
			return err
		}
	}

	return nil
}

func (w *SSHConfigWriter) writeServer(writer *bufio.Writer, server domain.Server) error {
	if _, err := fmt.Fprintf(writer, "Host %s\n", server.Alias); err != nil {
		return err
	}

	if server.Host != "" {
		if _, err := fmt.Fprintf(writer, "    HostName %s\n", server.Host); err != nil {
			return err
		}
	}

	if server.User != "" {
		if _, err := fmt.Fprintf(writer, "    User %s\n", server.User); err != nil {
			return err
		}
	}

	if server.Port != 0 && server.Port != DefaultPort {
		if _, err := fmt.Fprintf(writer, "    Port %d\n", server.Port); err != nil {
			return err
		}
	}

	if server.Key != "" {
		// Convert absolute paths to relative paths for cross-platform portability
		keyPath := w.toRelativePath(server.Key)
		if _, err := fmt.Fprintf(writer, "    IdentityFile %s\n", keyPath); err != nil {
			return err
		}
	}
	return nil
}

// toRelativePath converts absolute paths to tilde-prefixed relative paths when possible
func (w *SSHConfigWriter) toRelativePath(path string) string {
	// Already a relative path, return as-is
	if strings.HasPrefix(path, "~/") {
		return path
	}

	// Get user's home directory
	home, err := os.UserHomeDir()
	if err != nil {
		// Unable to get home directory, return original path
		return path
	}

	// Clean paths for consistency
	cleanPath := filepath.Clean(path)
	cleanHome := filepath.Clean(home)

	// Check if path is under home directory
	if strings.HasPrefix(cleanPath, cleanHome) {
		// Convert absolute path to relative
		relPath := strings.TrimPrefix(cleanPath, cleanHome)
		if relPath == "" {
			return "~"
		}
		// Ensure forward slashes for cross-platform compatibility
		relPath = filepath.ToSlash(relPath)
		if !strings.HasPrefix(relPath, "/") {
			relPath = "/" + relPath
		}
		return "~" + relPath
	}

	// Path is not under home directory, return original
	return path
}
