package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	device := flag.String(
		"device",
		"",
		"ATA device (\"list\" to list ATA devices)",
	)

	serial := flag.String(
		"serial",
		"",
		"ATA device serial number (\"list\" to list ATA devices)",
	)

	passwd := flag.String(
		"passwd",
		"",
		"Path to 32-byte binary password file",
	)

	operation := flag.String(
		"op",
		"unlock",
		"ATA security operation (\"help\" to list supported operations)",
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

	noreadpart := flag.Bool(
		"noreadpart",
		false,
		"do not reread the partition table after the ATA command",
	)

	verbose := flag.Bool(
		"verbose",
		false,
		"show CDB and Payload bytes being transmitted to the ATA drive.",
	)

	flag.Parse()

	if *serial == "list" || *device == "list" {
		disks, err := listDevices()

		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to list disks: %s\n", err)
			os.Exit(1)
		}

		for _, disk := range disks {
			fmt.Printf("/dev/%s: %s [%s]\n", disk.Name, disk.Serial, disk.Model)
		}

		os.Exit(0)
	}

	if *serial != "" {
		var err error

		*device, err = findSerial(*serial)

		if err != nil || *device == "" {
			fmt.Fprintf(os.Stderr, "failed to find %s: %s\n", *serial, err)
			os.Exit(1)
		}

		fmt.Printf("%s is at %s\n", *serial, *device)
	}

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
		*noreadpart,
		*verbose,
		*device,
		*passwd,
	); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
