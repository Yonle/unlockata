package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	SG_IO = 0x2285

	SG_DXFER_TO_DEV = -2

	ATA_PASS_THROUGH_16 = 0x85

	// SAT protocol 5 = PIO Data-Out.
	SAT_PROTO_PIO_DATA_OUT = 5

	// Sense descriptor requested.
	SG_FLAG_LUN_INHIBIT = 0x00000040
)

type sgIOHdr struct {
	InterfaceID    int32
	DxferDirection int32
	CmdLen         uint8
	MxSbLen        uint8
	IovecCount     uint16
	DxferLen       uint32
	Dxferp         uint64
	Cmdp           uint64
	Sbp            uint64
	Timeout        uint32
	Flags          uint32
	PackID         int32
	UsrPtr         uint64

	Status       uint8
	MaskedStatus uint8
	MsgStatus    uint8
	SbLenWr      uint8
	HostStatus   uint16
	DriverStatus uint16
	Resid        int32
	Duration     uint32
	Info         uint32
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
	master, maximum bool,
	device, passwordFile string,
) error {
	cdb := buildSecurityCDB(ataOp)
	var payload [512]byte
	var dxferDirection int32
	var dxferLen uint32
	var dxferPtr uint64

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

		dxferDirection = SG_DXFER_TO_DEV
		dxferLen = uint32(len(payload))
		dxferPtr = uint64(uintptr(unsafe.Pointer(&payload[0])))

	case PayloadNone:
		// No data payload.

	default:
		return fmt.Errorf(
			"unsupported payload type: %d",
			ataOp.PayloadType,
		)
	}

	fmt.Printf("CDB: %x\n", cdb)
	fmt.Printf("PAYLOAD: %x\n", payload)

	var sense [32]byte

	hdr := sgIOHdr{
		InterfaceID:    'S',
		DxferDirection: dxferDirection,

		CmdLen:   uint8(len(cdb)),
		MxSbLen:  uint8(len(sense)),
		DxferLen: dxferLen,

		Dxferp: dxferPtr,
		Cmdp:   uint64(uintptr(unsafe.Pointer(&cdb[0]))),
		Sbp:    uint64(uintptr(unsafe.Pointer(&sense[0]))),

		// 10 seconds.
		Timeout: 10_000,

		Flags: SG_FLAG_LUN_INHIBIT,
	}

	fd, err := unix.Open(
		device,
		unix.O_RDWR|unix.O_NONBLOCK,
		0,
	)
	if err != nil {
		return fmt.Errorf("open %s: %w", device, err)
	}
	defer unix.Close(fd)

	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(SG_IO),
		uintptr(unsafe.Pointer(&hdr)),
	)
	if errno != 0 {
		return fmt.Errorf("SG_IO: %w", errno)
	}

	if hdr.Status != 0 || hdr.Info&0x01 != 0 {
		fmt.Printf("SENSE: %x\n", sense[:hdr.SbLenWr])

		return fmt.Errorf(
			"ATA command failed: SCSI status=0x%02x host=0x%04x driver=0x%04x",
			hdr.Status,
			hdr.HostStatus,
			hdr.DriverStatus,
		)
	}

	if hdr.Info&0x01 != 0 {
		return errors.New("SG_IO reports command failure")
	}

	return nil
}

func main() {
	device := flag.String(
		"device",
		"",
		"ATA device (e.g. /dev/sda)",
	)

	passwd := flag.String(
		"passwd",
		"",
		"Path to 32-byte binary password file",
	)

	operation := flag.String(
		"op",
		"unlock",
		"ATA security operation",
	)

	useMaster := flag.Bool(
		"master",
		false,
		"use the ATA master password instead of the user password",
	)

	maximum := flag.Bool(
		"maximum",
		false,
		"use maximum security level",
	)

	flag.Parse()

	if *device == "" {
		flag.Usage()
		os.Exit(2)
	}

	ataOp, err := handleOperation(*operation)

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if *maximum && !ataOp.CanMaximum {
		fmt.Fprintln(os.Stderr, "-maximum only makes sense with -op set.")
		fmt.Fprintln(os.Stderr, "unset -maximum if you're not doing -op set.")
		os.Exit(1)
	}

	if ataOp.PayloadType == PayloadSecurityPassword && *passwd == "" {
		fmt.Fprintln(os.Stderr, "-passwd is required for this operation.")
		os.Exit(2)
	}

	if !confirmDestructive(ataOp) {
		return
	}

	if err := execute(
		ataOp,
		*useMaster,
		*maximum,
		*device,
		*passwd,
	); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
