package ui

import "testing"

func TestCleanCellText(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"plain text", "1.2.3.4", "1.2.3.4"},
		{"with spaces", "  hello  ", "hello"},
		{"yellow tag", "[yellow]1.2.3.4[-]", "1.2.3.4"},
		{"red bold", "[red::b]ALERT[-]", "ALERT"},
		{"nested colors", "[green]OK[white] 200[yellow] GET[-]", "OK 200 GET"},
		{"hex color", "[#ff0000]error[-]", "error"},
		{"compound tag", "[yellow:black:b]header[-]", "header"},
		{"just dash tag", "[-]text", "text"},
		{"IP with port", "[cyan]192.168.1.1:8080[-]", "192.168.1.1:8080"},
		{"real bracket", "array[0]", "array[0]"},
		{"domain path", "[white]example.com /api/v2[-]", "example.com /api/v2"},
		{"percent", "[green]42%[-]", "42%"},
		{"multiple tags", "[red]1[white] [yellow]chrome[green] 42.1%[-]", "1 chrome 42.1%"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cleanCellText(tt.in)
			if got != tt.want {
				t.Errorf("cleanCellText(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestStripTviewTags(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"[yellow]hello[-]", "hello"},
		{"no tags here", "no tags here"},
		{"[bold]text", "text"},
		{"[unknown_not_color]keep", "[unknown_not_color]keep"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got := stripTviewTags(tt.in)
			if got != tt.want {
				t.Errorf("stripTviewTags(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestLooksLikeTviewTag(t *testing.T) {
	tests := []struct {
		tag  string
		want bool
	}{
		{"", true},
		{"-", true},
		{"::", true},
		{"red", true},
		{"yellow", true},
		{"#ff0000", true},
		{"red:black:b", true},
		{"yellow::bold", true},
		{"notacolor", false},
		{"hello world", false},
		{"1.2.3.4", false},
	}
	for _, tt := range tests {
		t.Run(tt.tag, func(t *testing.T) {
			got := looksLikeTviewTag(tt.tag)
			if got != tt.want {
				t.Errorf("looksLikeTviewTag(%q) = %v, want %v", tt.tag, got, tt.want)
			}
		})
	}
}

func TestB64encode(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"f", "Zg=="},
		{"fo", "Zm8="},
		{"foo", "Zm9v"},
		{"foobar", "Zm9vYmFy"},
		{"1.2.3.4", "MS4yLjMuNA=="},
		{"Hello, World!", "SGVsbG8sIFdvcmxkIQ=="},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got := b64encode([]byte(tt.in))
			if got != tt.want {
				t.Errorf("b64encode(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
