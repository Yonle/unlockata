package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func listDevices() ([]Disk, error) {
	entries, err := os.ReadDir("/sys/block")
	if err != nil {
		return nil, err
	}

	var disks []Disk

	for _, entry := range entries {
		name := entry.Name()
		base := filepath.Join("/sys/block", name)

		// Skip virtual block devices such as zram.
		if _, err := os.Stat(filepath.Join(base, "device")); err != nil {
			continue
		}

		device := "/dev/" + name

		info, err := identify(device)
		if err != nil {
			continue
		}

		disks = append(disks, Disk{
			Name:   name,
			Serial: info.Serial,
			Model:  info.Model,
		})
	}

	return disks, nil
}

func findSerial(serial string) (string, error) {
	disks, err := listDevices()
	if err != nil {
		return "", err
	}

	for _, disk := range disks {
		if disk.Serial == serial {
			return "/dev/" + disk.Name, nil
		}
	}

	return "", fmt.Errorf("device with serial %q not found", serial)
}
