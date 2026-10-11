package main

import (
	"bufio"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"
	"text/tabwriter"
)

// gauth-decoder は Google Authenticator のマイグレーション QR
// (otpauth-migration://offline?data=...) をデコードして可読テーブルを出力する。
//
// 入力は 1 行 1 QR。zbarimg 等の出力をそのまま受け付けるため、
// 先頭の "QR-Code:" プレフィックスは除去する。それ以外 (空行や
// "1 symbol found" 等の接尾出力) は otpauth-migration を含まなければ無視する。

func main() {
	in := io.Reader(os.Stdin)
	if len(os.Args) > 1 {
		f, err := os.Open(os.Args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, "gauth-decoder:", err)
			os.Exit(1)
		}
		defer f.Close()
		in = f
	}
	if err := run(in, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "gauth-decoder:", err)
		os.Exit(1)
	}
}

// run は入力全体を処理する。いずれかの行の復号に失敗しても処理を続け、
// 失敗があれば error を返す (呼び出し側は終了コード 1 にマップする)。
func run(in io.Reader, stdout, stderr io.Writer) error {
	sc := bufio.NewScanner(in)
	// 1 QR あたりの行はアカウント数に応じて数 KB に伸びるため余裕を持つ。
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	w := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	failed := 0
	for sc.Scan() {
		data, ok := extractData(sc.Text())
		if !ok {
			continue
		}
		raw, err := decodeBase64(data)
		var p *MigrationPayload
		if err == nil {
			p, err = Decode(raw)
		}
		if err != nil {
			failed++
			fmt.Fprintf(stderr, "gauth-decoder: 復号失敗: %v\n", err)
			continue
		}
		// バッチ注釈行はタブを持たないため、tabwriter に渡るとアラインメント
		// ブロックが分かれてヘッダとデータ列の位置がずれる。先に Flush して
		// から stdout へ直接書き、ペイロードごとに独立した表を作る。
		if err := w.Flush(); err != nil {
			return err
		}
		fmt.Fprintln(stdout, batchHeader(p))
		fmt.Fprintln(w, "ISSUER\tNAME\tTYPE\tALGO\tDIGITS\tSECRET (Base32)\tCOUNTER")
		for _, op := range p.OtpParameters {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				op.Issuer, op.Name, typeName(op.Type), algoName(op.Algorithm),
				digitsLabel(op.Digits), encodeSecret(op.Secret), counterLabel(op))
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if failed > 0 {
		return fmt.Errorf("%d 行の復号に失敗", failed)
	}
	return nil
}

// extractData は行から data パラメータの値を取り出す。
//
// 注意: net/url の Query() はクエリ規則に従い '+' をスペースへ変換してしまうため
// 使わない。GA 本体は '+' を %2B にエンコードするが、ツール由来の未エンコード
// base64 がそのまま渡ってくることもある。そこで '?' 以降を手切り出しし、
// '+' を変換しない PathUnescape で %XX のみデコードする。
func extractData(line string) (string, bool) {
	line = strings.TrimSpace(line)
	line = strings.TrimPrefix(line, "QR-Code:")
	i := strings.Index(line, "otpauth-migration:")
	if i < 0 {
		return "", false
	}
	q := strings.IndexByte(line[i:], '?')
	if q < 0 {
		return "", false
	}
	// base64 の文字種は A-Za-z0-9+/= で '&' を含まないため、'&' 分割は安全。
	for _, kv := range strings.Split(line[i+q+1:], "&") {
		v, found := strings.CutPrefix(kv, "data=")
		if !found {
			continue
		}
		if s, err := url.PathUnescape(v); err == nil {
			v = s
		}
		return v, true
	}
	return "", false
}

// decodeBase64 は標準文字種の base64 をデコードする。
// GA の出力はパディング付きだが、パディングなしも受け付ける。
// どちらも失敗した場合、パディングを挟んで連結された複数 base64
// (例: "gAA==Ci4...") としてチャンク分割にフォールバックする。
func decodeBase64(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return decodeConcatBase64(s)
}

// concatSplitter は連結 base64 をチャンクに分割する。
// 各チャンクは 0〜2 個の '=' で終わる (base64 の文字種に '=' は含まれないため
// '=' の連なりがチャンク境界)。
var concatSplitter = regexp.MustCompile(`[^=]+=*`)

// decodeConcatBase64 は複数 QR の data を手で連結した文字列を扱う。
//
// 複数 QR エクスポート (batch) を 1 文字列に繋ぐと '=' パディングの直後に
// 次のペイロードが来て単一の base64 としては復号できない。各チャンクは
// 完全な MigrationPayload であり、protobuf はメッセージのバイト連結が
// そのままマージと等価 (repeated は蓄積、singular は後勝ち) なため、
// チャンクごとにデコードして連結すれば統合ペイロードになる。
func decodeConcatBase64(s string) ([]byte, error) {
	tokens := concatSplitter.FindAllString(s, -1)
	if len(tokens) == 0 {
		return nil, errors.New("base64 が空")
	}
	var out []byte
	for i, tok := range tokens {
		b, err := base64.StdEncoding.DecodeString(tok)
		if err != nil {
			b, err = base64.RawStdEncoding.DecodeString(tok)
			if err != nil {
				return nil, fmt.Errorf("連結 base64 %d 個目 (%q): %w", i+1, tok, err)
			}
		}
		out = append(out, b...)
	}
	return out, nil
}

// batchHeader はペイロード単位の注釈行を作る。未設定 (0) の項目は省略する。
func batchHeader(p *MigrationPayload) string {
	var sb strings.Builder
	sb.WriteString("#")
	if p.Version != 0 {
		fmt.Fprintf(&sb, " version=%d", p.Version)
	}
	if p.BatchSize != 0 {
		fmt.Fprintf(&sb, " batch=%d/%d", p.BatchIndex, p.BatchSize)
	}
	if p.BatchID != 0 {
		fmt.Fprintf(&sb, " id=%d", p.BatchID)
	}
	fmt.Fprintf(&sb, " accounts=%d", len(p.OtpParameters))
	return sb.String()
}

// encodeSecret は Key URI Format 準拠で Base32 (パディングなし) に変換する。
func encodeSecret(secret []byte) string {
	if len(secret) == 0 {
		return ""
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
}

// enum 値の表示名。proto2 の optional 未設定 (0) は空欄にする。

func algoName(v int32) string {
	switch v {
	case 1:
		return "SHA1"
	case 2:
		return "SHA256"
	case 3:
		return "SHA512"
	case 4:
		return "MD5"
	}
	return ""
}

// digitsLabel は DigitCount enum (SIX=1, EIGHT=2) を桁数表示にする。
// enum 値そのもの (6/8) ではない点に注意。
func digitsLabel(v int32) string {
	switch v {
	case 1:
		return "6"
	case 2:
		return "8"
	}
	return ""
}

func typeName(v int32) string {
	switch v {
	case 1:
		return "HOTP"
	case 2:
		return "TOTP"
	}
	return ""
}

// counterLabel は HOTP のシーケンス番号。設定時のみ表示する。
func counterLabel(op OtpParam) string {
	if op.Counter == 0 {
		return ""
	}
	return fmt.Sprintf("%d", op.Counter)
}
