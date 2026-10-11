package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// OtpParam は OtpParameters メッセージに対応する。
type OtpParam struct {
	Secret    []byte
	Name      string
	Issuer    string
	Algorithm int32
	Digits    int32
	Type      int32
	Counter   int64
}

// MigrationPayload は最上位メッセージに対応する。
type MigrationPayload struct {
	OtpParameters []OtpParam
	Version       int32
	BatchSize     int32
	BatchIndex    int32
	BatchID       int32
}

// protobuf wire format の wireType。
const (
	wireVarint = 0
	wire64     = 1
	wireBytes  = 2
	wire32     = 5
)

// readVarint は b の先頭から varint を 1 つ読み、値と消費バイト数を返す。
func readVarint(b []byte) (uint64, int, error) {
	v, n := binary.Uvarint(b)
	if n == 0 {
		return 0, 0, io.ErrUnexpectedEOF // varint が続きを必要とする (終端バイトなし)
	}
	if n < 0 {
		return 0, 0, errors.New("varint が 64bit の桁あふれ")
	}
	return v, n, nil
}

// readBytes は wireType が wireBytes のフィールド値 (長さ varint + バイト列) を読む。
// 値と残りのバッファを返す。
func readBytes(b []byte) (val, rest []byte, err error) {
	l, n, err := readVarint(b)
	if err != nil {
		return nil, nil, err
	}
	if l > uint64(len(b)-n) {
		return nil, nil, io.ErrUnexpectedEOF
	}
	return b[n : n+int(l)], b[n+int(l):], nil
}

// skipField は未知のフィールドを読み飛ばし、消費バイト数を返す。
func skipField(b []byte, wireType uint64) (int, error) {
	switch wireType {
	case wireVarint:
		_, n, err := readVarint(b)
		return n, err
	case wire64:
		if len(b) < 8 {
			return 0, io.ErrUnexpectedEOF
		}
		return 8, nil
	case wireBytes:
		_, rest, err := readBytes(b)
		if err != nil {
			return 0, err
		}
		return len(b) - len(rest), nil
	case wire32:
		if len(b) < 4 {
			return 0, io.ErrUnexpectedEOF
		}
		return 4, nil
	default:
		// wireType 3/4 は廃止済みの group。GA の出力には現れない。
		return 0, fmt.Errorf("未対応の wireType: %d", wireType)
	}
}

// nextTag はフィールド番号と wireType を返し、タグ分進んだ残バッファを返す。
func nextTag(b []byte) (field, wireType uint64, rest []byte, err error) {
	tag, n, err := readVarint(b)
	if err != nil {
		return 0, 0, nil, err
	}
	field, wireType = tag>>3, tag&7
	if field == 0 {
		return 0, 0, nil, errors.New("フィールド番号 0 は不正")
	}
	return field, wireType, b[n:], nil
}

// Decode は MigrationPayload の wire format バイト列をパースする。
// 未知のフィールドは wireType に応じて読み飛ばす。
func Decode(b []byte) (*MigrationPayload, error) {
	p := &MigrationPayload{}
	for len(b) > 0 {
		field, wireType, rest, err := nextTag(b)
		if err != nil {
			return nil, err
		}
		b = rest
		switch field {
		case 1: // otp_parameters
			if wireType != wireBytes {
				return nil, fmt.Errorf("otp_parameters: wireType %d は不正", wireType)
			}
			var sub []byte
			sub, b, err = readBytes(b)
			if err != nil {
				return nil, fmt.Errorf("otp_parameters: %w", err)
			}
			op, err := decodeOtpParam(sub)
			if err != nil {
				return nil, fmt.Errorf("otp_parameters: %w", err)
			}
			p.OtpParameters = append(p.OtpParameters, op)
			continue
		case 2, 3, 4, 5: // version, batch_size, batch_index, batch_id
			if wireType != wireVarint {
				return nil, fmt.Errorf("フィールド %d: wireType %d は不正", field, wireType)
			}
			var v uint64
			v, b, err = readVarintAndAdvance(b)
			if err != nil {
				return nil, fmt.Errorf("フィールド %d: %w", field, err)
			}
			switch field {
			case 2:
				p.Version = int32(v)
			case 3:
				p.BatchSize = int32(v)
			case 4:
				p.BatchIndex = int32(v)
			case 5:
				p.BatchID = int32(v)
			}
		default:
			n, err := skipField(b, wireType)
			if err != nil {
				return nil, fmt.Errorf("フィールド %d: %w", field, err)
			}
			b = b[n:]
		}
	}
	return p, nil
}

// decodeOtpParam は OtpParameters メッセージをパースする。
func decodeOtpParam(b []byte) (OtpParam, error) {
	var op OtpParam
	for len(b) > 0 {
		field, wireType, rest, err := nextTag(b)
		if err != nil {
			return op, err
		}
		b = rest
		switch field {
		case 1, 2, 3: // secret, name, issuer
			if wireType != wireBytes {
				return op, fmt.Errorf("フィールド %d: wireType %d は不正", field, wireType)
			}
			var val []byte
			val, b, err = readBytes(b)
			if err != nil {
				return op, fmt.Errorf("フィールド %d: %w", field, err)
			}
			switch field {
			case 1:
				op.Secret = val
			case 2:
				op.Name = string(val)
			case 3:
				op.Issuer = string(val)
			}
		case 4, 5, 6, 7: // algorithm, digits, type, counter
			if wireType != wireVarint {
				return op, fmt.Errorf("フィールド %d: wireType %d は不正", field, wireType)
			}
			var v uint64
			v, b, err = readVarintAndAdvance(b)
			if err != nil {
				return op, fmt.Errorf("フィールド %d: %w", field, err)
			}
			switch field {
			case 4:
				op.Algorithm = int32(v)
			case 5:
				op.Digits = int32(v)
			case 6:
				op.Type = int32(v)
			case 7:
				op.Counter = int64(v)
			}
		default:
			n, err := skipField(b, wireType)
			if err != nil {
				return op, fmt.Errorf("フィールド %d: %w", field, err)
			}
			b = b[n:]
		}
	}
	return op, nil
}

// readVarintAndAdvance は varint を読んで進んだ残バッファも返す。
func readVarintAndAdvance(b []byte) (uint64, []byte, error) {
	v, n, err := readVarint(b)
	if err != nil {
		return 0, nil, err
	}
	return v, b[n:], nil
}
