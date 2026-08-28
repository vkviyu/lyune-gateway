package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func TestRoundTripExchange(t *testing.T) {
	open, _ := NewOpen(DestService, 1, 0, ResponseRequired, 0, []byte("first"))
	data, _ := NewData(FlagEOF, []byte("last"))

	var encoded bytes.Buffer
	if err := WriteFrame(&encoded, open); err != nil {
		t.Fatal(err)
	}
	if err := WriteFrame(&encoded, data); err != nil {
		t.Fatal(err)
	}

	gotOpen, err := ReadFrame(&encoded)
	if err != nil {
		t.Fatal(err)
	}
	gotData, err := ReadFrame(&encoded)
	if err != nil {
		t.Fatal(err)
	}
	if gotOpen.Header != open.Header || !bytes.Equal(gotOpen.Body, open.Body) {
		t.Fatalf("OPEN mismatch: got=%+v want=%+v", gotOpen, open)
	}
	if gotData.Header != data.Header || !bytes.Equal(gotData.Body, data.Body) {
		t.Fatalf("DATA mismatch: got=%+v want=%+v", gotData, data)
	}
}

func TestResponseNoneRoundTripAndValidation(t *testing.T) {
	want, err := NewOpen(DestService, 1, 2, ResponseNone, FlagEOF, []byte("typing"))
	if err != nil {
		t.Fatal(err)
	}
	var encoded bytes.Buffer
	if err := WriteFrame(&encoded, want); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFrame(&encoded)
	if err != nil {
		t.Fatal(err)
	}
	if got.Header.Response != ResponseNone {
		t.Fatalf("response mode = %d, want none", got.Header.Response)
	}

	_, err = ReadFrame(bytes.NewReader([]byte{0x00, 0, 0, 0, 0x01, 2, 0, 0}))
	if !errors.Is(err, ErrUnknownResponse) {
		t.Fatalf("expected response mode error, got %v", err)
	}
}

func TestParsesAuthGrantAndTargetList(t *testing.T) {
	grant := make([]byte, 12+4)
	binary.BigEndian.PutUint64(grant[0:8], 77)
	binary.BigEndian.PutUint32(grant[8:12], 3600)
	copy(grant[12:], "json")
	destID, ttl, opaque, err := ParseAuthGrant(grant)
	if err != nil || destID != 77 || ttl != 3600 || string(opaque) != "json" {
		t.Fatalf("unexpected grant dest=%d ttl=%d opaque=%q err=%v", destID, ttl, opaque, err)
	}

	body := make([]byte, 2+16+3)
	binary.BigEndian.PutUint16(body[0:2], 2)
	binary.BigEndian.PutUint64(body[2:10], 5)
	binary.BigEndian.PutUint64(body[10:18], 9)
	copy(body[18:], "msg")
	targets, payload, err := ParseTargetList(body)
	if err != nil || len(targets) != 2 || targets[0] != 5 || targets[1] != 9 || string(payload) != "msg" {
		t.Fatalf("unexpected list targets=%v payload=%q err=%v", targets, payload, err)
	}
}
