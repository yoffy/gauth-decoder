package main

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

// 期待値は https://github.com/google/google-authenticator/wiki/Key-Uri-Format
// の例 (secret=JBSWY3DPEHPK3PXP) と一致する。
const fixture = "CjEKCkhlbGxvId6tvu8SGEV4YW1wbGU6YWxpY2VAZ29vZ2xlLmNvbRoHRXhhbXBsZTAC"

func fixtureBytes(t *testing.T) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(fixture)
	if err != nil {
		t.Fatalf("fixture base64: %v", err)
	}
	return b
}

func TestDecodeFixture(t *testing.T) {
	p, err := Decode(fixtureBytes(t))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(p.OtpParameters) != 1 {
		t.Fatalf("accounts = %d, want 1", len(p.OtpParameters))
	}
	op := p.OtpParameters[0]
	wantSecret := append([]byte("Hello!"), 0xde, 0xad, 0xbe, 0xef)
	if !bytes.Equal(op.Secret, wantSecret) {
		t.Errorf("Secret = %x, want %x", op.Secret, wantSecret)
	}
	if got := encodeSecret(op.Secret); got != "JBSWY3DPEHPK3PXP" {
		t.Errorf("encodeSecret = %q, want JBSWY3DPEHPK3PXP", got)
	}
	if op.Name != "Example:alice@google.com" {
		t.Errorf("Name = %q", op.Name)
	}
	if op.Issuer != "Example" {
		t.Errorf("Issuer = %q", op.Issuer)
	}
	if op.Type != 2 {
		t.Errorf("Type = %d, want 2 (TOTP)", op.Type)
	}
	// このフィクスチャは algorithm / digits / counter 未設定 (proto2 optional)。
	if op.Algorithm != 0 || op.Digits != 0 || op.Counter != 0 {
		t.Errorf("unset fields: algo=%d digits=%d counter=%d", op.Algorithm, op.Digits, op.Counter)
	}
}

func TestDecodeUnknownFieldsSkipped(t *testing.T) {
	// フィクスチャの末尾に未知フィールドを追加する:
	// field 8 varint (0x40 0x2A), field 9 bytes (0x4A 0x02 "hi")
	b := append(fixtureBytes(t), 0x40, 0x2a, 0x4a, 0x02, 'h', 'i')
	p, err := Decode(b)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(p.OtpParameters) != 1 || p.OtpParameters[0].Issuer != "Example" {
		t.Fatalf("未知フィールドスキップ後に内容が壊れた: %+v", p)
	}
}

func TestDecodeBatchFields(t *testing.T) {
	// field 2 version=1, field 3 batch_size=3, field 4 batch_index=2, field 5 batch_id=99
	b := append(fixtureBytes(t), 0x10, 0x01, 0x18, 0x03, 0x20, 0x02, 0x28, 0x63)
	p, err := Decode(b)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if p.Version != 1 || p.BatchSize != 3 || p.BatchIndex != 2 || p.BatchID != 99 {
		t.Errorf("batch fields = %+v", p)
	}
}

func TestDecodeErrors(t *testing.T) {
	full := fixtureBytes(t)
	cases := []struct {
		name string
		b    []byte
	}{
		{"切り詰め (長さ指定未満)", full[:20]},
		{"タグのみ", []byte{0x0a}},
		{"varint 桁あふれ", []byte{0x10, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01}},
		{"フィールド番号 0", []byte{0x00, 0x00}},
		{"未対応 wireType (group)", []byte{0x0b, 0x01}},
	}
	for _, tc := range cases {
		if _, err := Decode(tc.b); err == nil {
			t.Errorf("%s: エラーを期待", tc.name)
		}
	}
}

func TestDecodeEmpty(t *testing.T) {
	p, err := Decode(nil)
	if err != nil {
		t.Fatalf("Decode(nil): %v", err)
	}
	if len(p.OtpParameters) != 0 {
		t.Errorf("accounts = %d, want 0", len(p.OtpParameters))
	}
}

func TestExtractData(t *testing.T) {
	cases := []struct {
		line string
		want string
		ok   bool
	}{
		{"QR-Code:otpauth-migration://offline?data=ABC", "ABC", true},
		{"otpauth-migration://offline?data=ABC", "ABC", true},
		{"  QR-Code:otpauth-migration://offline?data=ABC  ", "ABC", true},
		// 未エンコード base64 の '+' はスペースへ変換してはいけない (Query() との差異)
		{"otpauth-migration://offline?data=+/8=", "+/8=", true},
		{"otpauth-migration://offline?data=%2B%2F8%3D", "+/8=", true},
		{"otpauth-migration://offline?foo=1&data=ABC", "ABC", true},
		{"1 symbol found", "", false},
		{"", "", false},
		{"otpauth-migration://offline", "", false},
		{"otpauth-migration://offline?other=1", "", false},
	}
	for _, tc := range cases {
		got, ok := extractData(tc.line)
		if ok != tc.ok || got != tc.want {
			t.Errorf("extractData(%q) = %q, %v; want %q, %v", tc.line, got, ok, tc.want, tc.ok)
		}
	}
}

func TestDecodeBase64Padding(t *testing.T) {
	// "hi" = aGk= (パディング付き) / aGk (なし)。両方受け付ける。
	for _, s := range []string{"aGk=", "aGk"} {
		b, err := decodeBase64(s)
		if err != nil || string(b) != "hi" {
			t.Errorf("decodeBase64(%q) = %q, %v; want \"hi\", nil", s, b, err)
		}
	}
	if _, err := decodeBase64("a"); err == nil {
		t.Error("不正な base64 でエラーを期待")
	}
}

func TestDecodeBase64Concat(t *testing.T) {
	// パディングの直後に次のペイロードが連結された形式 (gAA==Ci4... の実例版)。
	// chunk1 は fixture + version フィールド (56 バイト → base64 が '=' 終わり)、
	// chunk2 は fixture 本体 (54 バイト → パディングなし)。
	fx := fixtureBytes(t)
	chunk1 := base64.StdEncoding.EncodeToString(append(append([]byte{}, fx...), 0x10, 0x01))
	chunk2 := base64.StdEncoding.EncodeToString(fx)
	if !strings.HasSuffix(chunk1, "=") {
		t.Fatalf("テスト前提: chunk1 がパディング付きではない: %s", chunk1)
	}
	raw, err := decodeBase64(chunk1 + chunk2)
	if err != nil {
		t.Fatalf("decodeBase64 連結: %v", err)
	}
	p, err := Decode(raw)
	if err != nil {
		t.Fatalf("Decode 連結: %v", err)
	}
	// protobuf のバイト連結 = メッセージマージなのでアカウントが蓄積する。
	if len(p.OtpParameters) != 2 {
		t.Fatalf("accounts = %d, want 2", len(p.OtpParameters))
	}
	if p.Version != 1 {
		t.Errorf("Version = %d, want 1", p.Version)
	}
	for i, op := range p.OtpParameters {
		if got := encodeSecret(op.Secret); got != "JBSWY3DPEHPK3PXP" {
			t.Errorf("account %d secret = %q", i, got)
		}
	}
}

func TestDecodeConcatPaddedChunks(t *testing.T) {
	// パディングで終わるチャンクの直後に次のチャンクが来る形。
	// "aGk=" ("hi") を 2 つ連結したもの。
	b, err := decodeBase64("aGk=aGk=")
	if err != nil {
		t.Fatalf("decodeBase64: %v", err)
	}
	if string(b) != "hihi" {
		t.Errorf("= %q, want hihi", b)
	}
}

func TestRunEndToEnd(t *testing.T) {
	in := "QR-Code:otpauth-migration://offline?data=" + fixture + "\n1 symbol found\n"
	var out, errOut bytes.Buffer
	if err := run(strings.NewReader(in), &out, &errOut); err != nil {
		t.Fatalf("run: %v (stderr: %s)", err, errOut.String())
	}
	got := out.String()
	for _, want := range []string{"ISSUER", "JBSWY3DPEHPK3PXP", "TOTP", "Example", "accounts=1"} {
		if !strings.Contains(got, want) {
			t.Errorf("出力に %q がない:\n%s", want, got)
		}
	}
	if errOut.Len() != 0 {
		t.Errorf("stderr が空でない: %s", errOut.String())
	}
}

func TestRunFailureContinues(t *testing.T) {
	in := "QR-Code:otpauth-migration://offline?data=@@@invalid\n" +
		"QR-Code:otpauth-migration://offline?data=" + fixture + "\n"
	var out, errOut bytes.Buffer
	err := run(strings.NewReader(in), &out, &errOut)
	if err == nil {
		t.Fatal("失敗行があるのに nil を返した")
	}
	// 失敗行があっても 2 行目は出力されていること。
	if !strings.Contains(out.String(), "JBSWY3DPEHPK3PXP") {
		t.Errorf("正常行が出力されていない:\n%s", out.String())
	}
}
