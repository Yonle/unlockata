package main

import "fmt"

var senseKeyNames = map[byte]string{
	0x00: "NO SENSE",
	0x01: "RECOVERED ERROR",
	0x02: "NOT READY",
	0x03: "MEDIUM ERROR",
	0x04: "HARDWARE ERROR",
	0x05: "ILLEGAL REQUEST",
	0x06: "UNIT ATTENTION",
	0x07: "DATA PROTECT",
	0x08: "BLANK CHECK",
	0x09: "VENDOR-SPECIFIC",
	0x0A: "COPY ABORTED",
	0x0B: "ABORTED COMMAND",
	0x0C: "EQUAL",
	0x0D: "VOLUME OVERFLOW",
	0x0E: "MISCOMPARE",
}

var ascNames = map[[2]byte]string{
	{0x20, 0x00}: "INVALID COMMAND OPERATION CODE",
	{0x21, 0x00}: "LOGICAL BLOCK ADDRESS OUT OF RANGE",
	{0x24, 0x00}: "INVALID FIELD IN CDB",
	{0x25, 0x00}: "LOGICAL UNIT NOT SUPPORTED",
	{0x26, 0x00}: "INVALID FIELD IN PARAMETER LIST",
	{0x27, 0x00}: "WRITE PROTECTED",
	{0x29, 0x00}: "POWER ON, RESET, OR BUS DEVICE RESET OCCURRED",
	{0x2C, 0x00}: "COMMAND SEQUENCE ERROR",
	{0x3A, 0x00}: "MEDIUM NOT PRESENT",
	{0x44, 0x00}: "INTERNAL TARGET FAILURE",
	{0x47, 0x00}: "SCSI PARITY ERROR",
	{0x48, 0x00}: "INITIATOR DETECTED ERROR MESSAGE RECEIVED",
	{0x4E, 0x00}: "OVERLAPPED COMMANDS ATTEMPTED",
	{0x53, 0x00}: "MEDIA LOAD OR EJECT FAILED",
	{0x55, 0x00}: "SYSTEM RESOURCE FAILURE",
}

func parseSense(sense []byte) string {
	if len(sense) < 2 {
		return "invalid sense data"
	}

	responseCode := sense[0] & 0x7f

	switch responseCode {
	case 0x70, 0x71:
		if len(sense) < 14 {
			return "invalid fixed-format sense data"
		}

		senseKey := sense[2] & 0x0f
		asc := sense[12]
		ascq := sense[13]

		return formatSense(senseKey, asc, ascq)

	case 0x72, 0x73:
		if len(sense) < 8 {
			return "invalid descriptor-format sense data"
		}

		senseKey := sense[1] & 0x0f
		asc := sense[2]
		ascq := sense[3]

		return formatSense(senseKey, asc, ascq)

	default:
		return fmt.Sprintf(
			"unknown sense format: response code 0x%02x",
			responseCode,
		)
	}
}

func formatSense(senseKey, asc, ascq byte) string {
	keyName := senseKeyNames[senseKey]
	if keyName == "" {
		keyName = "UNKNOWN"
	}

	ascName := ascNames[[2]byte{asc, ascq}]
	if ascName == "" {
		ascName = "UNKNOWN"
	}

	return fmt.Sprintf(
		"Sense Key: 0x%02x (%s), ASC/ASCQ: 0x%02x/0x%02x (%s)",
		senseKey,
		keyName,
		asc,
		ascq,
		ascName,
	)
}
