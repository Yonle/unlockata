package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
)

const (
	ATA_PASS_THROUGH_16 = 0x85

	SAT_PROTO_PIO_DATA_IN  = 4
	SAT_PROTO_PIO_DATA_OUT = 5
	SAT_PROTO_NON_DATA     = 3
)

type ATAResult struct {
	Sense []byte

	Status       uint8
	HostStatus   uint16
	DriverStatus uint16
	Info         uint32

	Payload []byte
}

type Disk struct {
	Name   string
	Model  string
	Serial string
}

func ataString(data []byte, word, words int) string {
	start := word * 2
	end := start + words*2

	if start < 0 || end > len(data) {
		return ""
	}

	buf := make([]byte, end-start)

	for i := start; i < end; i += 2 {
		buf[i-start] = data[i+1]
		buf[i-start+1] = data[i]
	}

	return strings.TrimSpace(string(buf))
}

func buildIdentifyCDB() [16]byte {
	var cdb [16]byte

	cdb[0] = ATA_PASS_THROUGH_16

	// PIO Data-In
	cdb[1] = SAT_PROTO_PIO_DATA_IN << 1

	// T_LENGTH=2, BYT_BLOK=1, T_DIR=1
	cdb[2] = 0x0e

	// 512-byte transfer = 1 block
	cdb[6] = 1

	// ATA IDENTIFY DEVICE
	cdb[14] = 0xec

	return cdb
}

func buildSecurityCDB(command ATASecurityCommand) [16]byte {
	var cdb [16]byte

	cdb[0] = ATA_PASS_THROUGH_16

	if command.DataOut {
		// PIO Data-Out, 512-byte block transfer.
		cdb[1] = SAT_PROTO_PIO_DATA_OUT << 1
		cdb[2] = 0x06 // T_LENGTH=2, BYT_BLOK=1, T_DIR=0

		if command.DataBytes == 0 || command.DataBytes%512 != 0 {
			panic("invalid ATA data transfer size")
		}

		blocks := command.DataBytes / 512
		if blocks > 255 {
			panic("ATA PASS-THROUGH transfer too large")
		}

		cdb[6] = byte(blocks)
	} else {
		cdb[1] = SAT_PROTO_NON_DATA << 1
	}

	// ATA command selected by -op.
	cdb[14] = command.Code

	return cdb
}

func buildSecurityPasswordPayload(password []byte, master, maximum bool) [512]byte {
	var payload [512]byte
	var control uint16

	if master {
		control |= 1 << 0 // Identifier = Master
	}

	if maximum {
		control |= 1 << 8 // Security level = Maximum
	}

	binary.LittleEndian.PutUint16(payload[0:2], control)
	copy(payload[2:34], password)

	return payload // [passwordkind][32 bytes of password]
}

func execute(
	ataOp ATASecurityCommand,
	master, maximum, noreadpart, verbose bool,
	device, passwordFile string,
) error {
	cdb := buildSecurityCDB(ataOp)
	var payload [512]byte

	switch ataOp.PayloadType {
	case PayloadSecurityPassword:
		password, err := os.ReadFile(passwordFile)
		if err != nil {
			return fmt.Errorf("read password: %w", err)
		}

		if len(password) != 32 {
			return fmt.Errorf(
				"password must be exactly 32 bytes, got %d",
				len(password),
			)
		}
		payload = buildSecurityPasswordPayload(
			password,
			master,
			maximum,
		)

	case PayloadNone:
		// No data payload.

	default:
		return fmt.Errorf(
			"unsupported payload type: %d",
			ataOp.PayloadType,
		)
	}

	if verbose {
		fmt.Printf("CDB: %x\n", cdb)
		fmt.Printf("PAYLOAD: %x\n", payload)
	}

	r, err := ataExec(
		device,
		ataOp.PayloadType,
		cdb,
		&payload,
		noreadpart,
	)

	if err != nil {
		return err
	}

	if r.Status != 0 || r.Info&0x01 != 0 {
		if len(r.Sense) > 0 {
			fmt.Printf("SENSE: %x\n", r.Sense)
			fmt.Printf("SENSE DECODED: %s\n", parseSense(r.Sense))
		}

		if r.Info&0x01 != 0 {
			return errors.New("SG_IO reports command failure")
		}

		return fmt.Errorf(
			"ATA command failed: SCSI status=0x%02x host=0x%04x driver=0x%04x",
			r.Status,
			r.HostStatus,
			r.DriverStatus,
		)
	}

	return nil
}
