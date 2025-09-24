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
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

func NewHintBar() *tview.TextView {
	hint := tview.NewTextView().SetDynamicColors(true)
	hint.SetBackgroundColor(tcell.Color233)
	hint.SetText("[#BBBBBB]Press [::b]/[-:-:b] to search…  •  ↑↓ Navigate  •  Enter SSH  •  c Copy SSH  •  g/G Ping (All)  •  r Refresh  •  a Add  •  e Edit  •  t Tags  •  d Delete  •  p Pin/Unpin  •  s Sort[-]")
	return hint
}
