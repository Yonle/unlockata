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

	noreadpart := flag.Bool(
		"noreadpart",
		false,
		"do not reread the partition table after the ATA command",
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
		*noreadpart,
		*device,
		*passwd,
	); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
