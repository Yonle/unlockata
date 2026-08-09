# unlockata

A small Go utility for sending ATA Security commands through Linux `SG_IO`.

Primarily intended for unlocking ATA Security-locked drives using a 32-byte binary password.

Supports ATA Security operations such as `unlock`, `set`, `freeze`, `erase`, and `disable`.

## Building

Requires Go and Linux with `SG_IO` support.

```sh
go build -o unlockata .
```
