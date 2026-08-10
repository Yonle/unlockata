package main

import (
	"fmt"
	"os"
)

type ATAPayloadType int
type ATASecurityCommand struct {
	Code        byte
	Name        string
	DataOut     bool
	DataBytes   int
	Destructive bool
	CanMaximum  bool
	PayloadType ATAPayloadType
}

type ATAIdentify struct {
	Serial   string
	Model    string
	Firmware string
}

const (
	PayloadNone ATAPayloadType = iota
	PayloadSecurityPassword
	PayloadIdentify
)

var ataSecurityOperationNames = []string{
	"set",
	"unlock",
	"freeze",
	"erase",
	"erase-prepare",
	"disable",
}

var ataSecurityCommands = map[string]ATASecurityCommand{
	"set": {
		Code:        0xF1,
		Name:        "SECURITY SET PASSWORD",
		DataOut:     true,
		DataBytes:   512,
		CanMaximum:  true,
		PayloadType: PayloadSecurityPassword,
	},
	"unlock": {
		Code:        0xF2,
		Name:        "SECURITY UNLOCK",
		DataOut:     true,
		DataBytes:   512,
		PayloadType: PayloadSecurityPassword,
	},
	"erase-prepare": {
		Code:        0xF3,
		Name:        "SECURITY ERASE PREPARE",
		Destructive: true,
	},
	"erase": {
		Code:        0xF4,
		Name:        "SECURITY ERASE UNIT",
		DataOut:     true,
		DataBytes:   512,
		Destructive: true,
		PayloadType: PayloadSecurityPassword,
	},
	"freeze": {
		Code: 0xF5,
		Name: "SECURITY FREEZE LOCK",
	},
	"disable": {
		Code:        0xF6,
		Name:        "SECURITY DISABLE PASSWORD",
		DataOut:     true,
		DataBytes:   512,
		PayloadType: PayloadSecurityPassword,
	},
}

func handleOperation(op string) (ATASecurityCommand, error) {
	if op == "help" {
		fmt.Println("Available ATA security operations:")
		for _, name := range ataSecurityOperationNames {
			command := ataSecurityCommands[name]
			fmt.Printf("  %-16s %s (0x%02x)\n",
				name,
				command.Name,
				command.Code,
			)
		}

		os.Exit(0)
	}

	command, ok := ataSecurityCommands[op]
	if !ok {
		return ATASecurityCommand{}, fmt.Errorf(
			"unknown ATA security operation %q",
			op,
		)
	}

	return command, nil
}

func confirmDestructive(command ATASecurityCommand) bool {
	if !command.Destructive {
		return true
	}

	fmt.Printf(
		"WARNING: %s is destructive and may permanently destroy data.\n",
		command.Name,
	)
	fmt.Print("Type 'YES' to continue: ")

	var answer string
	fmt.Scanln(&answer)

	return answer == "YES"
}

func identify(device string) (ATAIdentify, error) {
	cdb := buildIdentifyCDB()

	var payload [512]byte

	r, err := ataExec(
		device,
		PayloadIdentify,
		cdb,
		&payload,
		true,
	)
	if err != nil {
		return ATAIdentify{}, err
	}

	if r.Status != 0 || r.Info&0x01 != 0 {
		return ATAIdentify{}, fmt.Errorf(
			"IDENTIFY DEVICE failed: status=0x%02x host=0x%04x driver=0x%04x",
			r.Status,
			r.HostStatus,
			r.DriverStatus,
		)
	}

	return ATAIdentify{
		Serial:   ataString(r.Payload, 10, 10),
		Firmware: ataString(r.Payload, 23, 4),
		Model:    ataString(r.Payload, 27, 20),
	}, nil
}
