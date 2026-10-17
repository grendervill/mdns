// Package doq implements the DNS-over-QUIC message framing of
// RFC 9250: every DNS message carried on a QUIC stream is preceded by
// its length as a two-byte big-endian integer.
package doq

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// MaxMessageSize is the largest DNS message the two-byte length prefix
// can describe.
const MaxMessageSize = 65535

// ErrEmptyMessage is returned for a zero-length DNS message, which the
// framing cannot represent.
var ErrEmptyMessage = errors.New("doq: empty message")

// WriteMessage writes msg to w with its length prefix.
func WriteMessage(w io.Writer, msg []byte) error {
	if len(msg) == 0 {
		return ErrEmptyMessage
	}
	if len(msg) > MaxMessageSize {
		return fmt.Errorf("doq: message of %d bytes exceeds %d", len(msg), MaxMessageSize)
	}

	var prefix [2]byte
	binary.BigEndian.PutUint16(prefix[:], uint16(len(msg)))
	if _, err := w.Write(prefix[:]); err != nil {
		return fmt.Errorf("doq: write length: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("doq: write message: %w", err)
	}
	return nil
}

// ReadMessage reads one length-prefixed message from r. A prefix of
// zero is refused; a stream that ends before the promised length is an
// error wrapping io.ErrUnexpectedEOF.
func ReadMessage(r io.Reader) ([]byte, error) {
	var prefix [2]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return nil, fmt.Errorf("doq: read length: %w", err)
	}

	size := binary.BigEndian.Uint16(prefix[:])
	if size == 0 {
		return nil, ErrEmptyMessage
	}

	msg := make([]byte, size)
	if _, err := io.ReadFull(r, msg); err != nil {
		return nil, fmt.Errorf("doq: read message: %w", err)
	}
	return msg, nil
}
