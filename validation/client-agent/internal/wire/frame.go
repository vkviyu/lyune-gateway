package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	ALPN        = "lyune/2"
	MaxBodySize = 1<<16 - 1
)

type FrameType uint8

const (
	FrameOpen FrameType = 0x00
	FrameData FrameType = 0x01
)

type DestKind uint8

const (
	DestGateway   DestKind = 0x00
	DestService   DestKind = 0x01
	DestPeer      DestKind = 0x02
	DestMulticast DestKind = 0x03
)

type Flags uint8

const (
	FlagEOF    Flags = 1 << 0
	FlagReport Flags = 1 << 1
	knownFlags       = FlagEOF | FlagReport | Flags(1<<2)
)

func (f Flags) IsEOF() bool { return f&FlagEOF != 0 }

type ResponseMode uint8

const (
	ResponseRequired ResponseMode = 0x00
	ResponseNone     ResponseMode = 0x01
)

type Header struct {
	Type     FrameType    `json:"type"`
	Flags    Flags        `json:"flags"`
	BodyLen  uint16       `json:"body_len"`
	DestKind DestKind     `json:"dest_kind"`
	Response ResponseMode `json:"response_mode"`
	Group    uint8        `json:"group"`
	RouteKey uint8        `json:"route_key"`
}

type Frame struct {
	Header Header `json:"header"`
	Body   []byte `json:"-"`
}

var (
	ErrUnknownFrameType = errors.New("unknown frame type")
	ErrUnknownDestKind  = errors.New("unknown destination kind")
	ErrUnknownResponse  = errors.New("unknown response mode")
	ErrReservedBits     = errors.New("reserved bits are set")
	ErrBodyTooLarge     = errors.New("frame body exceeds uint16")
)

func NewOpen(dest DestKind, group, routeKey uint8, response ResponseMode, flags Flags, body []byte) (*Frame, error) {
	if len(body) > MaxBodySize {
		return nil, ErrBodyTooLarge
	}
	if err := validateDest(dest); err != nil {
		return nil, err
	}
	if err := validateResponse(response); err != nil {
		return nil, err
	}
	return &Frame{
		Header: Header{
			Type:     FrameOpen,
			Flags:    flags,
			BodyLen:  uint16(len(body)),
			DestKind: dest,
			Response: response,
			Group:    group,
			RouteKey: routeKey,
		},
		Body: body,
	}, nil
}

func NewData(flags Flags, body []byte) (*Frame, error) {
	if len(body) > MaxBodySize {
		return nil, ErrBodyTooLarge
	}
	return &Frame{Header: Header{Type: FrameData, Flags: flags, BodyLen: uint16(len(body))}, Body: body}, nil
}

func ReadFrame(r io.Reader) (*Frame, error) {
	var prefix [4]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return nil, err
	}

	header := Header{
		Type:    FrameType(prefix[0]),
		Flags:   Flags(prefix[1]),
		BodyLen: binary.BigEndian.Uint16(prefix[2:4]),
	}
	if header.Flags&^knownFlags != 0 || (header.Type == FrameData && header.Flags&FlagReport != 0) {
		return nil, ErrReservedBits
	}

	switch header.Type {
	case FrameOpen:
		var suffix [4]byte
		if _, err := io.ReadFull(r, suffix[:]); err != nil {
			return nil, err
		}
		header.DestKind = DestKind(suffix[0])
		if err := validateDest(header.DestKind); err != nil {
			return nil, err
		}
		header.Response = ResponseMode(suffix[1])
		if err := validateResponse(header.Response); err != nil {
			return nil, err
		}
		header.Group = suffix[2]
		header.RouteKey = suffix[3]
	case FrameData:
	default:
		return nil, fmt.Errorf("%w: 0x%02x", ErrUnknownFrameType, header.Type)
	}

	body := make([]byte, int(header.BodyLen))
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return &Frame{Header: header, Body: body}, nil
}

func WriteFrame(w io.Writer, frame *Frame) error {
	if len(frame.Body) > MaxBodySize {
		return ErrBodyTooLarge
	}
	if frame.Header.Flags&^knownFlags != 0 || (frame.Header.Type == FrameData && frame.Header.Flags&FlagReport != 0) {
		return ErrReservedBits
	}

	headerSize := 4
	if frame.Header.Type == FrameOpen {
		headerSize = 8
		if err := validateDest(frame.Header.DestKind); err != nil {
			return err
		}
	} else if frame.Header.Type != FrameData {
		return ErrUnknownFrameType
	}

	header := make([]byte, headerSize)
	header[0] = byte(frame.Header.Type)
	header[1] = byte(frame.Header.Flags)
	binary.BigEndian.PutUint16(header[2:4], uint16(len(frame.Body)))
	if frame.Header.Type == FrameOpen {
		header[4] = byte(frame.Header.DestKind)
		if err := validateResponse(frame.Header.Response); err != nil {
			return err
		}
		header[5] = byte(frame.Header.Response)
		header[6] = frame.Header.Group
		header[7] = frame.Header.RouteKey
	}
	if _, err := w.Write(header); err != nil {
		return err
	}
	if len(frame.Body) > 0 {
		_, err := w.Write(frame.Body)
		return err
	}
	return nil
}

func validateDest(dest DestKind) error {
	switch dest {
	case DestGateway, DestService, DestPeer, DestMulticast:
		return nil
	default:
		return fmt.Errorf("%w: 0x%02x", ErrUnknownDestKind, dest)
	}
}

func validateResponse(response ResponseMode) error {
	switch response {
	case ResponseRequired, ResponseNone:
		return nil
	default:
		return fmt.Errorf("%w: 0x%02x", ErrUnknownResponse, response)
	}
}

func ParseAuthGrant(body []byte) (destID uint64, ttlSeconds uint32, opaque []byte, err error) {
	if len(body) < 12 {
		return 0, 0, nil, io.ErrUnexpectedEOF
	}
	return binary.BigEndian.Uint64(body[0:8]), binary.BigEndian.Uint32(body[8:12]), body[12:], nil
}

func ParseTargetList(body []byte) (targets []uint64, payload []byte, err error) {
	if len(body) < 2 {
		return nil, nil, io.ErrUnexpectedEOF
	}
	count := int(binary.BigEndian.Uint16(body[0:2]))
	prefix := 2 + count*8
	if len(body) < prefix {
		return nil, nil, io.ErrUnexpectedEOF
	}
	targets = make([]uint64, count)
	for index := range targets {
		offset := 2 + index*8
		targets[index] = binary.BigEndian.Uint64(body[offset : offset+8])
	}
	return targets, body[prefix:], nil
}
