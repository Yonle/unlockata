package main

import (
	"fmt"
	"golang.org/x/sys/unix"
	"unsafe"
)

const (
	SG_IO             = 0x2285
	SG_DXFER_NONE     = -1
	SG_DXFER_TO_DEV   = -2
	SG_DXFER_FROM_DEV = -3

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

func ataExec(
	device string,
	ataPType ATAPayloadType,
	cdb [16]byte,
	payload *[512]byte,
	noreadpart bool,
) (
	ataResult ATAResult,
	err error,
) {
	var sense [255]byte
	var dxferDirection int32
	var dxferLen uint32
	var dxferPtr uint64

	switch ataPType {
	case PayloadSecurityPassword:
		dxferDirection = SG_DXFER_TO_DEV
		dxferLen = uint32(len(payload))
		dxferPtr = uint64(uintptr(unsafe.Pointer(&payload[0])))

	case PayloadIdentify:
		dxferDirection = SG_DXFER_FROM_DEV
		dxferLen = uint32(len(payload))
		dxferPtr = uint64(uintptr(unsafe.Pointer(&payload[0])))

	case PayloadNone:
		dxferDirection = SG_DXFER_NONE
	}

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
		unix.O_RDONLY|unix.O_NONBLOCK,
		0,
	)

	if err != nil {
		err = fmt.Errorf("open %s: %w", device, err)
		return
	}
	defer unix.Close(fd)

	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(SG_IO),
		uintptr(unsafe.Pointer(&hdr)),
	)

	ataResult = ATAResult{
		Sense:        sense[:hdr.SbLenWr],
		Status:       hdr.Status,
		HostStatus:   hdr.HostStatus,
		DriverStatus: hdr.DriverStatus,
		Info:         hdr.Info,
	}

	ataResult.Payload = payload[:dxferLen]

	if errno != 0 {
		err = fmt.Errorf("SG_IO: %w", errno)
		return
	}

	if !noreadpart {
		_, _, errno := unix.Syscall(
			unix.SYS_IOCTL,
			uintptr(fd),
			uintptr(unix.BLKRRPART),
			0,
		)

		if errno != 0 {
			err = fmt.Errorf("reread partition table: %w", errno)
			return
		}
	}

	return
}
