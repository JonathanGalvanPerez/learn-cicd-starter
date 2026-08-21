package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		want    string
		wantErr error
	}{
		{
			name:    "no authorization header",
			headers: http.Header{},
			want:    "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "wrong authorization type",
			headers: http.Header{
				"Authorization": []string{"Bearer abc123"},
			},
			want:    "",
			wantErr: nil, // solo verificamos que exista un error
		},
		{
			name: "malformed authorization header",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			want:    "",
			wantErr: nil,
		},
		{
			name: "valid api key",
			headers: http.Header{
				"Authorization": []string{"ApiKey abc123"},
			},
			want:    "abc123",
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetAPIKey(tt.headers)

			if tt.wantErr == ErrNoAuthHeaderIncluded {
				if err != ErrNoAuthHeaderIncluded {
					t.Fatalf("expected ErrNoAuthHeaderIncluded, got %v", err)
				}
				return
			}

			if tt.want == "" {
				if err == nil {
					t.Fatal("expected an error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got != tt.want {
				t.Errorf("expected %q, got %q", tt.want, got)
			}
		})
	}
}
