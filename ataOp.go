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

const (
	PayloadNone ATAPayloadType = iota
	PayloadSecurityPassword
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
	"freeze": {
		Code: 0xF3,
		Name: "SECURITY FREEZE LOCK",
	},
	"erase": {
		Code:        0xF4,
		Name:        "SECURITY ERASE UNIT",
		DataOut:     true,
		DataBytes:   512,
		Destructive: true,
		PayloadType: PayloadSecurityPassword,
	},
	"erase-prepare": {
		Code:        0xF5,
		Name:        "SECURITY ERASE PREPARE",
		DataOut:     true,
		DataBytes:   512,
		Destructive: true,
	},
	"disable": {
		Code:      0xF6,
		Name:      "SECURITY DISABLE PASSWORD",
		DataOut:   true,
		DataBytes: 512,
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
