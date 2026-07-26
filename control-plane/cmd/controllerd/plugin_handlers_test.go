package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// wasmPreamble is a minimal valid WebAssembly header: "\0asm" + version 1.
var wasmPreamble = []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}

const goodManifest = `
[plugin]
name = "rate-guard"
version = "1.2.3"
description = "Blocks noisy clients"
author = "Sentinel Labs"

[plugin.hooks]
request_headers = true

[plugin.permissions]
host_log = true
host_set_decision = true
`

// buildZip assembles an in-memory archive from name→content pairs, preserving
// insertion order.
func buildZip(t *testing.T, files [][2]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range files {
		w, err := zw.Create(f[0])
		require.NoError(t, err)
		_, err = w.Write([]byte(f[1]))
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

func TestParsePluginZipHappyPath(t *testing.T) {
	z := buildZip(t, [][2]string{
		{"sentinel-plugin.toml", goodManifest},
		{"plugin.wasm", string(wasmPreamble)},
	})
	p, err := parsePluginZip(z)
	require.NoError(t, err)
	require.Equal(t, "rate-guard", p.manifest.Plugin.Name)
	require.Equal(t, "1.2.3", p.manifest.Plugin.Version)
	require.True(t, p.manifest.Plugin.Hooks.RequestHeaders)
	require.True(t, p.manifest.Plugin.Permissions.HostSetDecision)
	require.False(t, p.manifest.Plugin.Permissions.HostKvSet)

	sum := sha256.Sum256(wasmPreamble)
	require.Equal(t, hex.EncodeToString(sum[:]), p.sha256,
		"digest must be over the module bytes so the data plane can verify what it fetched")
}

// Zipping a directory (the normal thing a user does) nests every entry one level
// deep. That must work, or the feature fails for most real uploads.
func TestParsePluginZipAcceptsOneLevelOfNesting(t *testing.T) {
	z := buildZip(t, [][2]string{
		{"rate-guard/sentinel-plugin.toml", goodManifest},
		{"rate-guard/plugin.wasm", string(wasmPreamble)},
	})
	p, err := parsePluginZip(z)
	require.NoError(t, err)
	require.Equal(t, "rate-guard", p.manifest.Plugin.Name)
}

func TestParsePluginZipHonoursCustomWasmPath(t *testing.T) {
	m := strings.Replace(goodManifest, `author = "Sentinel Labs"`,
		"author = \"Sentinel Labs\"\nwasm = \"build/guard.wasm\"", 1)
	z := buildZip(t, [][2]string{
		{"sentinel-plugin.toml", m},
		{"build/guard.wasm", string(wasmPreamble)},
	})
	p, err := parsePluginZip(z)
	require.NoError(t, err)
	require.Len(t, p.wasm, len(wasmPreamble))
}

func TestParsePluginZipRejections(t *testing.T) {
	cases := []struct {
		name  string
		files [][2]string
		want  string
	}{
		{
			name:  "no manifest",
			files: [][2]string{{"plugin.wasm", string(wasmPreamble)}},
			want:  "must contain sentinel-plugin.toml",
		},
		{
			name:  "missing module",
			files: [][2]string{{"sentinel-plugin.toml", goodManifest}},
			want:  "does not contain the module",
		},
		{
			name: "module is not wasm",
			files: [][2]string{
				{"sentinel-plugin.toml", goodManifest},
				{"plugin.wasm", "#!/bin/sh\nrm -rf /\n"},
			},
			want: "not a WebAssembly module",
		},
		{
			name: "manifest missing name",
			files: [][2]string{
				{"sentinel-plugin.toml", "[plugin]\nversion = \"1.0.0\"\n"},
				{"plugin.wasm", string(wasmPreamble)},
			},
			want: "must set both plugin.name and plugin.version",
		},
		{
			name: "unsafe plugin name",
			files: [][2]string{
				{"sentinel-plugin.toml", "[plugin]\nname = \"../../etc/passwd\"\nversion = \"1\"\n"},
				{"plugin.wasm", string(wasmPreamble)},
			},
			want: "is invalid",
		},
		{
			name: "uppercase plugin name",
			files: [][2]string{
				{"sentinel-plugin.toml", "[plugin]\nname = \"RateGuard\"\nversion = \"1\"\n"},
				{"plugin.wasm", string(wasmPreamble)},
			},
			want: "is invalid",
		},
		{
			name: "traversal in wasm path",
			files: [][2]string{
				{"sentinel-plugin.toml", "[plugin]\nname = \"ok\"\nversion = \"1\"\nwasm = \"../../../etc/shadow\"\n"},
				{"plugin.wasm", string(wasmPreamble)},
			},
			want: "unsafe",
		},
		{
			name: "two manifests is ambiguous",
			files: [][2]string{
				{"sentinel-plugin.toml", goodManifest},
				{"other/sentinel-plugin.toml", goodManifest},
				{"plugin.wasm", string(wasmPreamble)},
			},
			want: "more than one",
		},
		{
			name: "unknown manifest key",
			files: [][2]string{
				{"sentinel-plugin.toml", "[plugin]\nname = \"ok\"\nversion = \"1\"\nrun_as_root = true\n"},
				{"plugin.wasm", string(wasmPreamble)},
			},
			want: "is not valid",
		},
		{
			name:  "not a zip at all",
			files: nil,
			want:  "not a readable .zip archive",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var data []byte
			if tc.files == nil {
				data = []byte("this is definitely not a zip file")
			} else {
				data = buildZip(t, tc.files)
			}
			_, err := parsePluginZip(data)
			require.Error(t, err, "must be rejected")
			require.Contains(t, err.Error(), tc.want)
		})
	}
}

// An archive may not smuggle an escaping entry name even though nothing is ever
// extracted to disk: the names are matched against and logged.
func TestSafeZipNameRejectsEscapes(t *testing.T) {
	for _, bad := range []string{
		"", "/etc/passwd", "../secret", "../../a/b", "..",
		`windows\path\file`, "/",
	} {
		_, ok := safeZipName(bad)
		require.False(t, ok, "must reject %q", bad)
	}
	for _, good := range []string{
		"sentinel-plugin.toml", "dir/plugin.wasm", "./plugin.wasm", "a/b/c.wasm",
	} {
		_, ok := safeZipName(good)
		require.True(t, ok, "must accept %q", good)
	}
}

// A zip entry that declares a huge uncompressed size must not be allowed to
// allocate it. This is the decompression-bomb guard: the entry below expands to
// far more than the manifest ceiling from a tiny compressed payload.
func TestReadZipEntryBoundsDecompressionBombs(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("sentinel-plugin.toml")
	require.NoError(t, err)
	// 1 MiB of a single repeated byte compresses to almost nothing.
	_, err = w.Write(bytes.Repeat([]byte("A"), 1<<20))
	require.NoError(t, err)
	require.NoError(t, zw.Close())

	zr, err := zip.NewReader(newByteReaderAt(buf.Bytes()), int64(buf.Len()))
	require.NoError(t, err)
	require.Len(t, zr.File, 1)

	_, err = readZipEntry(zr.File[0], 4096)
	require.Error(t, err)
	require.Contains(t, err.Error(), "exceeds the 4096 byte limit")
}

func TestPluginNameRegex(t *testing.T) {
	for _, ok := range []string{"a", "rate-guard", "jwt.validator", "x_1", strings.Repeat("a", 64)} {
		require.True(t, pluginNameRe.MatchString(ok), "should accept %q", ok)
	}
	for _, bad := range []string{
		"", "-leading", ".dot", "UPPER", "has space", "semi;colon",
		"../trav", "sub/dir", strings.Repeat("a", 65),
	} {
		require.False(t, pluginNameRe.MatchString(bad), "should reject %q", bad)
	}
}
