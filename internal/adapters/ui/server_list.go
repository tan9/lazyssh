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

package ui

import (
	"github.com/Adembc/lazyssh/internal/core/domain"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

type ServerList struct {
	*tview.List
	servers           []domain.Server
	onSelection       func(domain.Server)
	onSelectionChange func(domain.Server)
	currentWidth      int
}

func NewServerList() *ServerList {
	list := &ServerList{
		List: tview.NewList(),
	}
	list.build()
	return list
}

func (sl *ServerList) build() {
	sl.List.ShowSecondaryText(false)
	sl.List.SetBorder(true).
		SetTitle(" Servers ").
		SetTitleAlign(tview.AlignCenter).
		SetBorderColor(tcell.Color238).
		SetTitleColor(tcell.Color250)
	sl.List.
		SetSelectedBackgroundColor(tcell.Color24).
		SetSelectedTextColor(tcell.Color255).
		SetHighlightFullLine(true)

	sl.List.SetChangedFunc(func(index int, mainText string, secondaryText string, shortcut rune) {
		if index >= 0 && index < len(sl.servers) && sl.onSelectionChange != nil {
			sl.onSelectionChange(sl.servers[index])
		}
	})
}

func (sl *ServerList) UpdateServers(servers []domain.Server) {
	// Save current selection before clearing
	currentIdx := sl.List.GetCurrentItem()
	var currentAlias string
	if currentIdx >= 0 && currentIdx < len(sl.servers) {
		currentAlias = sl.servers[currentIdx].Alias
	}

	sl.servers = servers
	sl.List.Clear()

	// Get current width
	_, _, width, _ := sl.List.GetInnerRect() //nolint:dogsled
	sl.currentWidth = width

	newSelectedIdx := -1
	for i := range servers {
		primary, secondary := formatServerLine(servers[i], width)
		idx := i
		sl.List.AddItem(primary, secondary, 0, func() {
			if sl.onSelection != nil {
				sl.onSelection(sl.servers[idx])
			}
		})
		// Track the new index of previously selected server
		if currentAlias != "" && servers[i].Alias == currentAlias {
			newSelectedIdx = i
		}
	}

	if sl.List.GetItemCount() > 0 {
		// Restore previous selection if found, otherwise keep first item
		if newSelectedIdx >= 0 {
			sl.List.SetCurrentItem(newSelectedIdx)
			if sl.onSelectionChange != nil {
				sl.onSelectionChange(sl.servers[newSelectedIdx])
			}
		} else {
			sl.List.SetCurrentItem(0)
			if sl.onSelectionChange != nil {
				sl.onSelectionChange(sl.servers[0])
			}
		}
	}
}

// RefreshDisplay re-renders the list with current width
func (sl *ServerList) RefreshDisplay() {
	_, _, width, _ := sl.List.GetInnerRect() //nolint:dogsled
	if width != sl.currentWidth {
		sl.currentWidth = width
		// Save current selection
		currentIdx := sl.List.GetCurrentItem()
		// Re-render
		sl.UpdateServers(sl.servers)
		// Restore selection
		if currentIdx >= 0 && currentIdx < sl.List.GetItemCount() {
			sl.List.SetCurrentItem(currentIdx)
		}
	}
}

func (sl *ServerList) GetSelectedServer() (domain.Server, bool) {
	idx := sl.List.GetCurrentItem()
	if idx >= 0 && idx < len(sl.servers) {
		return sl.servers[idx], true
	}
	return domain.Server{}, false
}

func (sl *ServerList) OnSelection(fn func(server domain.Server)) *ServerList {
	sl.onSelection = fn
	return sl
}

func (sl *ServerList) OnSelectionChange(fn func(server domain.Server)) *ServerList {
	sl.onSelectionChange = fn
	return sl
}
