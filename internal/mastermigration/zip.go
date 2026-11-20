package mastermigration

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
)

// The migration format uses a deliberately small ZIP subset: stored entries,
// UTF-8 names, no data descriptors, and no ZIP64. This avoids accepting a
// decompression bomb and keeps archive validation independent of host tools.
type zipEntry struct {
	name string
	data []byte
}

func writeStoredZip(entries []zipEntry) ([]byte, error) {
	if len(entries) == 0 || len(entries) > 65535 {
		return nil, ErrInvalidArchive
	}
	type centralRecord struct {
		name              []byte
		crc, size, offset uint32
	}
	central := make([]centralRecord, 0, len(entries))
	var output bytes.Buffer
	for _, entry := range entries {
		name := []byte(entry.name)
		if len(name) == 0 || len(name) > 65535 || len(entry.data) > int(^uint32(0)) {
			return nil, ErrInvalidArchive
		}
		record := centralRecord{name: name, crc: crc32.ChecksumIEEE(entry.data), size: uint32(len(entry.data)), offset: uint32(output.Len())}
		_ = binary.Write(&output, binary.LittleEndian, uint32(0x04034b50))
		_ = binary.Write(&output, binary.LittleEndian, uint16(20))
		_ = binary.Write(&output, binary.LittleEndian, uint16(0x0800))
		_ = binary.Write(&output, binary.LittleEndian, uint16(0))
		_ = binary.Write(&output, binary.LittleEndian, uint16(0))
		_ = binary.Write(&output, binary.LittleEndian, uint16(0))
		_ = binary.Write(&output, binary.LittleEndian, record.crc)
		_ = binary.Write(&output, binary.LittleEndian, record.size)
		_ = binary.Write(&output, binary.LittleEndian, record.size)
		_ = binary.Write(&output, binary.LittleEndian, uint16(len(name)))
		_ = binary.Write(&output, binary.LittleEndian, uint16(0))
		output.Write(name)
		output.Write(entry.data)
		central = append(central, record)
	}
	centralOffset := uint32(output.Len())
	for _, record := range central {
		_ = binary.Write(&output, binary.LittleEndian, uint32(0x02014b50))
		_ = binary.Write(&output, binary.LittleEndian, uint16(20))
		_ = binary.Write(&output, binary.LittleEndian, uint16(20))
		_ = binary.Write(&output, binary.LittleEndian, uint16(0x0800))
		_ = binary.Write(&output, binary.LittleEndian, uint16(0))
		_ = binary.Write(&output, binary.LittleEndian, uint16(0))
		_ = binary.Write(&output, binary.LittleEndian, uint16(0))
		_ = binary.Write(&output, binary.LittleEndian, record.crc)
		_ = binary.Write(&output, binary.LittleEndian, record.size)
		_ = binary.Write(&output, binary.LittleEndian, record.size)
		_ = binary.Write(&output, binary.LittleEndian, uint16(len(record.name)))
		_ = binary.Write(&output, binary.LittleEndian, uint16(0))
		_ = binary.Write(&output, binary.LittleEndian, uint16(0))
		_ = binary.Write(&output, binary.LittleEndian, uint16(0))
		_ = binary.Write(&output, binary.LittleEndian, uint16(0))
		_ = binary.Write(&output, binary.LittleEndian, uint32(0))
		_ = binary.Write(&output, binary.LittleEndian, record.offset)
		output.Write(record.name)
	}
	centralSize := uint32(output.Len()) - centralOffset
	_ = binary.Write(&output, binary.LittleEndian, uint32(0x06054b50))
	_ = binary.Write(&output, binary.LittleEndian, uint16(0))
	_ = binary.Write(&output, binary.LittleEndian, uint16(0))
	_ = binary.Write(&output, binary.LittleEndian, uint16(len(central)))
	_ = binary.Write(&output, binary.LittleEndian, uint16(len(central)))
	_ = binary.Write(&output, binary.LittleEndian, centralSize)
	_ = binary.Write(&output, binary.LittleEndian, centralOffset)
	_ = binary.Write(&output, binary.LittleEndian, uint16(0))
	return output.Bytes(), nil
}

func readStoredZip(encoded []byte) (map[string][]byte, error) {
	if len(encoded) < 22 || len(encoded) > maxArchiveBytes {
		return nil, ErrInvalidArchive
	}
	eocd := len(encoded) - 22
	if binary.LittleEndian.Uint32(encoded[eocd:]) != 0x06054b50 {
		return nil, ErrInvalidArchive
	}
	count := int(binary.LittleEndian.Uint16(encoded[eocd+10:]))
	centralSize := int(binary.LittleEndian.Uint32(encoded[eocd+12:]))
	centralOffset := int(binary.LittleEndian.Uint32(encoded[eocd+16:]))
	if count == 0 || centralOffset < 0 || centralSize < 0 || centralOffset+centralSize != eocd {
		return nil, ErrInvalidArchive
	}
	result := make(map[string][]byte, count)
	position := centralOffset
	for index := 0; index < count; index++ {
		if position+46 > eocd || binary.LittleEndian.Uint32(encoded[position:]) != 0x02014b50 {
			return nil, ErrInvalidArchive
		}
		flags := binary.LittleEndian.Uint16(encoded[position+8:])
		method := binary.LittleEndian.Uint16(encoded[position+10:])
		crc := binary.LittleEndian.Uint32(encoded[position+16:])
		compressed := int(binary.LittleEndian.Uint32(encoded[position+20:]))
		uncompressed := int(binary.LittleEndian.Uint32(encoded[position+24:]))
		nameLength := int(binary.LittleEndian.Uint16(encoded[position+28:]))
		extraLength := int(binary.LittleEndian.Uint16(encoded[position+30:]))
		commentLength := int(binary.LittleEndian.Uint16(encoded[position+32:]))
		localOffset := int(binary.LittleEndian.Uint32(encoded[position+42:]))
		end := position + 46 + nameLength + extraLength + commentLength
		if flags != 0x0800 || method != 0 || compressed != uncompressed || uncompressed > maxArchiveFileBytes || nameLength == 0 || end > eocd {
			return nil, ErrInvalidArchive
		}
		name := string(encoded[position+46 : position+46+nameLength])
		if !cleanArchiveName(name) {
			return nil, ErrInvalidArchive
		}
		if _, duplicate := result[name]; duplicate {
			return nil, ErrInvalidArchive
		}
		if localOffset < 0 || localOffset+30 > centralOffset || binary.LittleEndian.Uint32(encoded[localOffset:]) != 0x04034b50 {
			return nil, ErrInvalidArchive
		}
		localNameLength := int(binary.LittleEndian.Uint16(encoded[localOffset+26:]))
		localExtraLength := int(binary.LittleEndian.Uint16(encoded[localOffset+28:]))
		dataStart := localOffset + 30 + localNameLength + localExtraLength
		dataEnd := dataStart + compressed
		if localNameLength != nameLength || dataStart < 0 || dataEnd > centralOffset || string(encoded[localOffset+30:localOffset+30+localNameLength]) != name {
			return nil, ErrInvalidArchive
		}
		data := append([]byte(nil), encoded[dataStart:dataEnd]...)
		if crc32.ChecksumIEEE(data) != crc {
			return nil, ErrInvalidArchive
		}
		result[name] = data
		position = end
	}
	if position != eocd {
		return nil, errors.New("invalid ZIP central directory")
	}
	return result, nil
}
