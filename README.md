# gauth-decoder

Google Authenticator の「アカウントを転送」で出力される QR コード
(`otpauth-migration://offline?data=...`) をデコードして、アカウント一覧を
可読テーブルで表示する CLI ツール。依存ゼロの Go 実装 (protobuf ランタイム不入り、
wire format を直接パースする手書きパーサ)。

## ビルド

```sh
make build   # ./gauth-decoder を生成
make clean
```

## 使い方

zbarimg 等の QR リーダの出力をそのままパイプする。ファイル引数も可 (省略時 stdin)。

```sh
zbarimg -q --raw export.png | gauth-decoder
```

出力例:

```
# accounts=1
ISSUER   NAME                      TYPE  ALGO  DIGITS  SECRET (Base32)   COUNTER
Example  Example:alice@google.com  TOTP                JBSWY3DPEHPK3PXP
```

- 1 行 1 QR。`QR-Code:` プレフィックス (zbarimg の既定出力) は自動で除去。
  `1 symbol found` 等のそれ以外の行は無視する。
- 復号に失敗した行は stderr に出して続行し、1 行以上失敗すれば終了コード 1。

## 入力として受け付ける形

| 形 | 挙動 |
|---|---|
| `otpauth-migration://offline?data=<base64>` | 1 ペイロードとしてデコード |
| 上記の複数行 (複数 QR を 1 行 1 本で渡す) | 行ごとに独立したテーブル |
| data 値を手で連結したもの (`...==Ci4...` のようにパディングの直後に次が続く) | チャンク分割して統合 1 ペイロードとして表示 |

連結入力を統合できるのは、protobuf ではメッセージのバイト連結がそのまま
マージと等価 (repeated フィールドは蓄積、singular フィールドは後勝ち) なため。
各 QR は完全な `MigrationPayload` なので、デコード後につなげれば 1 ペイロードになる。

## 挙動の注意 (コードから復元しにくい理由)

- `data` の抽出に `net/url` の `Query()` は使っていない。クエリ解析規則では
  `+` がスペースに変換され base64 が壊れるため。`?` 以降を手切り出して
  `PathUnescape` (`%XX` のみデコードし `+` は保持) を使っている。GA 本体は `+` を
  `%2B` にエンコードするが、ツール由来の未エンコード base64 も通す。
- base64 はパディングあり (`StdEncoding`) / なし (`RawStdEncoding`) 両対応。
  どちらも失敗した場合のみ連結形式とみなし、`=` 境界でチャンク分割して再挑戦する。
- digits は enum が SIX=1 / EIGHT=2 で、桁数そのもの (6/8) ではない。
- TOTP の周期 (period) はペイロードに含まれない。GA は 30 秒固定。
- 複数 QR エクスポート (batch) の行をまたいだマージはしない。行が別なら表も別。
  1 文字列に連結して渡した場合のみ統合される。

## セキュリティ注意

出力には OTP シークレットそのものが平文で出る。他人の見える端末やログで
実行しないこと。

## 開発

```sh
go test ./...
```
