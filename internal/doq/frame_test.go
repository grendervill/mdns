package doq_test

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"mydns/internal/doq"
)

// TestFrameRoundtrip checks the RFC 9250 framing: a message written to
// a stream comes back byte for byte, with the two-byte length prefix
// consumed.
func TestFrameRoundtrip(t *testing.T) {
	msg := []byte{0x12, 0x34, 0xab, 0xcd}

	var buf bytes.Buffer
	if err := doq.WriteMessage(&buf, msg); err != nil {
		t.Fatalf("WriteMessage() = %v, want nil", err)
	}
	if got, want := buf.Len(), len(msg)+2; got != want {
		t.Fatalf("written bytes = %d, want %d (message plus two-byte length)", got, want)
	}
	if got := buf.Bytes()[:2]; !bytes.Equal(got, []byte{0x00, 0x04}) {
		t.Errorf("length prefix = %x, want 0004", got)
	}

	got, err := doq.ReadMessage(&buf)
	if err != nil {
		t.Fatalf("ReadMessage() = %v, want nil", err)
	}
	if !bytes.Equal(got, msg) {
		t.Errorf("ReadMessage() = %x, want %x", got, msg)
	}
}

// TestWriteRejectsEmpty checks that an empty message is refused rather
// than framed with a zero length.
func TestWriteRejectsEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := doq.WriteMessage(&buf, nil); err == nil {
		t.Fatalf("WriteMessage(nil) = nil error, want an error")
	}
}

// TestWriteRejectsOversized checks the two-byte length limit: 65636
// bytes cannot be framed.
func TestWriteRejectsOversized(t *testing.T) {
	var buf bytes.Buffer
	if err := doq.WriteMessage(&buf, make([]byte, 65536)); err == nil {
		t.Fatalf("WriteMessage(65536 bytes) = nil error, want an error")
	}
}

// TestReadRejectsEmptyLength checks that a zero-length prefix is
// refused.
func TestReadRejectsEmptyLength(t *testing.T) {
	if _, err := doq.ReadMessage(bytes.NewReader([]byte{0x00, 0x00})); err == nil {
		t.Fatalf("ReadMessage(zero length) = nil error, want an error")
	}
}

// TestReadShortData checks that a length prefix promising more bytes
// than the stream delivers surfaces as an unexpected EOF.
func TestReadShortData(t *testing.T) {
	// Length says 10, only three bytes follow.
	_, err := doq.ReadMessage(bytes.NewReader([]byte{0x00, 0x0a, 0x01, 0x02, 0x03}))
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("ReadMessage(short) = %v, want io.ErrUnexpectedEOF", err)
	}
}
