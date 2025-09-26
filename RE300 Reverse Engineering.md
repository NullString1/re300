# Reverse Engineering The TP-Link RE300 WiFi Repeater

## Project overview
OpenWRT does not support the TP-Link RE300v1 currently (likely due to lack of ethernet port which is present on the RE305). 

This project adds support to OpenWRT for the re300 via direct flashing, adds support for the EN25QH64A flash chip to u-boot and provides a tool for modifying stock firmware and decrypting stock config files.

## Stock Firmware Analysis
### Popping U-Boot Shell On Stock Firmware
#### Connecting serial
Serial config:
`57600 8n1` 
_Note: you may need to disable hardware flow control_

TX, RX and GND pads are labelled and located near the bottom left of the device as shown in the picture where the yellow wires are soldered.

![[serial.jpg]]
#### Interrupting u-boot to open shell
Timing is very tight and you will likely have to try again many times before the magic string input times out. Just power off the device and repeat until you get shell prompt
1. Open serial console
2. Turn on RE300
3. Repeatedly press `4` until you see message asking for magic string
4. Type `tpl` very quickly and repeatedly
5. Notice shell prompt `=>`

### Dumping flash
#### Dumping with flash programmer (ch341a, rpi, etc) (RECOMMENDED)
If you have a ch341a flash programmer, raspberry pi, pi pico (with serprog firmware), or any other `flashrom` compatible device then this is the best method for you.

Using a SOP-8 chip clip is recommended as this is fastest and easiest way to connect to the chip. Otherwise, you can use individual pin clips (very hard) or solder wires directly to the chip. 

![[serial.jpg]]

1. Disconnect the device from power and open the cover 
2. Connect the flash chip to your programmer of choice *(ENSURE POWER IS NOT CONNECTED, YOU MAY KILL YOUR DEVICE AND YOUR PROGRAMMER)*
3. Setup the programmer
4. Run 
```sh 
flashrom -p {programmer_name}
```
1. Identify your flash chip from the output (likely EN25QH64A)
2. To dump your flash chip run 
```sh 
flashrom -p {programmer_name} -c {chip_name} --read flash_dump.bin
```


Example:
```sh
flashrom -p ch341a_spi
flashrom -p ch341a_spi -c en25qh64a --read flash_dump.bin
```

#### Dumping via u-boot shell
Dumping in u-boot is possible, however hard due to lack of any network interface to use tftp or similar. Instead we will have to dump over the serial connection which is obviously very slow (at least 45 minutes). 

To dump via u-boot shell use the following python script _Note: the script has not been extensively tested, I used it just once_
```python
import serial
import time
import os
import argparse
import signal
import sys

def parse_spi_read_output(output):
    lines = output.strip().splitlines()
    lines = [line for line in lines if line and not line.startswith("MT7628 #") and not line.startswith("spi read") and not line.startswith("read len:") and not line == ""]
    for line in lines:
        print(line[:50])
    data_line = lines[0]
    print(data_line[:50])
    # If there's a '>' prompt, cut it off
    tokens = data_line.strip().split()
    hex_bytes = []
    for t in tokens:
        if 1 <= len(t) <= 2:
            try:
                v = int(t, 16)
                if 0 <= v <= 0xFF:
                    hex_bytes.append(t)
            except ValueError:
                continue
    return bytes(int(b, 16) for b in hex_bytes)

def read_until_prompt(ser, prompt=b"MT7628 #"):
    output = b""
    start_time = time.time()
    while True:
        line = ser.readline()
        if not line:
            if time.time() - start_time > 10:
                break
            continue
        output += line
        if prompt in output:
            break
    return output.decode(errors='ignore')

def is_empty_or_ff(chunk):
    """Return True if all bytes are 0x00 or 0xFF (common erased flash patterns)."""
    return all(b == 0x00 for b in chunk) or all(b == 0xFF for b in chunk)

def main():
    parser = argparse.ArgumentParser(description="Dump SPI flash via U-Boot spi read command, auto-stopping if repeated patterns detected.")
    parser.add_argument('--serial', type=str, required=True, help="Serial port (e.g. /dev/ttyUSB0)")
    parser.add_argument('--baud', type=int, default=57600, help="Baudrate (default: 57600)")
    parser.add_argument('--outfile', type=str, default="spi_flash_dump.bin", help="Output file (default: spi_flash_dump.bin)")
    parser.add_argument('--size', type=lambda x: int(x, 0), default=0x1000000, help="Total flash size in bytes (default: 16MB/0x1000000)")
    parser.add_argument('--chunk', type=int, default=1000, help="Chunk size in bytes (default: 1000)")
    parser.add_argument('--repeat-stop', type=int, default=3, help="Stop if this many repeated identical non-empty chunks (default: 3)")
    args = parser.parse_args()

    resume_offset = 0
    if os.path.exists(args.outfile):
        resume_offset = os.path.getsize(args.outfile)
        print(f"Resuming at offset 0x{resume_offset:X}")

    last_chunk = None
    repeat_count = 0
    current_addr = resume_offset

    def signal_handler(signum, frame):
        print(f"\n\nInterrupted! Current state saved.")
        print(f"Dumped up to offset: 0x{current_addr:X}")
        print(f"Resume with: python dump.py --serial {args.serial} --baud {args.baud} --outfile {args.outfile} --size 0x{args.size:X} --chunk {args.chunk}")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    with serial.Serial(args.serial, args.baud, timeout=2) as ser, open(args.outfile, "ab" if resume_offset else "wb") as outf:
        addr = resume_offset
        while addr < args.size:
            current_addr = addr
            nbytes = min(args.chunk, args.size - addr)
            ser.reset_input_buffer()
            cmd = f"spi read {addr:x} {nbytes:x}\n"
            ser.write(cmd.encode())
            time.sleep(min(0.2, 0.01 * (nbytes // 16)))
            output = read_until_prompt(ser)
            chunk = parse_spi_read_output(output)
            if len(chunk) != nbytes:
                print(f"\nWarning: Expected {nbytes} bytes, got {len(chunk)} at 0x{addr:X}. Logging output.")
                with open(f"spi_error_{addr:08X}.log", "w") as f:
                    f.write(output)
                break
            # Pattern repeat detection
            if last_chunk is not None and chunk == last_chunk and not is_empty_or_ff(chunk):
                repeat_count += 1
                if repeat_count >= args.repeat_stop:
                    print(f"\nLikely end of real flash detected at 0x{addr:X} (saw {repeat_count} identical non-empty chunks).")
                    break
            else:
                repeat_count = 0
            last_chunk = chunk
            outf.write(chunk)
            outf.flush()
            print(f"\rRead 0x{addr:08X} / 0x{args.size:08X} ({len(chunk)} bytes)", end="")
            addr += nbytes
    print("\nDone.")

if __name__ == "__main__":
    main()
```

### Image layout

#### Flash dump

From partition table

| Offset     | Size       | Name            | String search              |
| ---------- | ---------- | --------------- | -------------------------- |
| 0x00000000 | 0x00020000 | fs-uboot        | "U-Boot (ver num)" - 13A50 |
| 0x00020000 | 0x000E0000 | os-image        | "TP-LINK Technologies" - 4 |
| 0x00100000 | 0x006C0000 | file-system     | "hsqse"                    |
| 0x007C0000 | 0x00002000 | partition-table | "partition" - C            |
| 0x007C2000 | 0x00000020 | default-mac     |                            |
| 0x007C2100 | 0x00000020 | pin             |                            |
| 0x007C3100 | 0x00001000 | product-info    |                            |
| 0x007C4200 | 0x00001000 | soft-version    |                            |
| 0x007C5200 | 0x00001000 | support-list    |                            |
| 0x007C6200 | 0x00008000 | profile         |                            |
| 0x007CE200 | 0x00000400 | config-info     |                            |
| 0x007D0000 | 0x00010000 | user-config     |                            |
| 0x007E0000 | 0x00010000 | default-config  |                            |
| 0x007F0000 | 0x00010000 | radio           |                            |

#### Firmware Image

| Offset     | Size     | Section            |     |
| ---------- | -------- | ------------------ | --- |
| 0x00000000 | 0x14     | Firmware Header    |     |
| 0x00000014 | 0x2000   | Unknown (All 0XFF) |     |
| 0x00002014 | 0x18460  | U-Boot             |     |
| 0x0001A475 | 0xD6A8F  | os-image           |     |
| 0x000F0F04 | 0x689A10 | file-system        |     |
### Firmware analysis
The stock firmware can be extracted from a flash dump, or [obtained from TP-Link](https://www.tp-link.com/uk/support/download/re300/v1/#Firmware)

Binwalk analysis shows the TP-Link firmware header, the linux kernel and the squashfs file system. 
```sh
binwalk ../re300v1_up-ver1-0-8-P1\[20211126-rel67847\]\ \(1\).bin --log log.json
```

| Offset | Size | Name | Confidence | Description |
| :--- | :--- | :--- | :--- | :--- |
| 99425 | 512 | tplink | 128 | TP-Link firmware header, kernel load address: 0x80000000, kernel entry point: 0x8000C150, header size: 512 bytes |
| 99937 | 878734 | lzma | 250 | LZMA compressed data, properties: 0x5D, dictionary size: 33554432 bytes, compressed size: 878734 bytes, uncompressed size: 2536732 bytes |
| 978672 | 6847340 | squashfs | 250 | SquashFS file system, little endian, version: 4.0, compression: xz, inode count: 1381, block size: 1048576, image size: 6847340 bytes, created: 2021-11-26 10:50:4
Extracting with binwalk will allow us to analyse the firmware
```sh
binwalk ../re300v1_up-ver1-0-8-P1\[20211126-rel67847\]\ \(1\).bin -e
```

Files of most interest are the compiled lua files under `squashfs-root/usr/lib/lua/luci/`
OpenWRT uses a modified version of lua, so the normal luadec will fail to decompile them. 
Instead we can use the modified versions of luadec:
- [luadec-openwrt](https://github.com/HandsomeYingyan/luadec-openwrt)
- [luadec-tplink](https://github.com/superkhung/luadec-tplink)
- [luadec-openwrt-tplinl](https://github.com/RE-Solver/luadec-openwrt-tplink)

These are not perfect and often decompiling fails, but disasembling is often enough to understand the code.
```sh
#decompile with
luadec ./path/to/file.lua
#disassemble with
luadec -dis ./path/to/file.lua
```
### Decrypting exported config.bin 
Disassembling the `squashfs-root/usr/lib/lua/luci/model/crypto.lua` script found in the stock firmware shows the following code:

```
   14 [-]: LOADK     R3 K8        ; R3 := "aes-256-cbc"
   15 [-]: LOADK     R4 K9        ; R4 := "openssl zlib -e %s | openssl "
   16 [-]: MOVE      R5 R3        ; R5 := R3
   17 [-]: LOADK     R6 K10       ; R6 := " -e %s"
   18 [-]: CONCAT    R4 R4 R6     ; R4 := concat(R4 to R6)
   19 [-]: LOADK     R5 K11       ; R5 := "openssl "
   20 [-]: MOVE      R6 R3        ; R6 := R3
   21 [-]: LOADK     R7 K12       ; R7 := " -d %s %s | openssl zlib -d"
   22 [-]: CONCAT    R5 R5 R7     ; R5 := concat(R5 to R7)
   23 [-]: LOADK     R6 K11       ; R6 := "openssl "
   24 [-]: MOVE      R7 R3        ; R7 := R3
   25 [-]: LOADK     R8 K13       ; R8 := " -e %s %s"
   26 [-]: CONCAT    R6 R6 R8     ; R6 := concat(R6 to R8)
   27 [-]: LOADK     R7 K11       ; R7 := "openssl "
   28 [-]: MOVE      R8 R3        ; R8 := R3
   29 [-]: LOADK     R9 K14       ; R9 := " -d %s %s"
   30 [-]: CONCAT    R7 R7 R9     ; R7 := concat(R7 to R9)
   31 [-]: LOADK     R8 K15       ; R8 := "-in %q"
   32 [-]: LOADK     R9 K16       ; R9 := "-k %q"
   33 [-]: LOADK     R10 K17      ; R10 := "-kfile /etc/secretkey"
   34 [-]: LOADK     R11 K9       ; R11 := "openssl zlib -e %s | openssl "
   35 [-]: MOVE      R12 R3       ; R12 := R3
   36 [-]: LOADK     R13 K10      ; R13 := " -e %s"
   37 [-]: CONCAT    R11 R11 R13  ; R11 := concat(R11 to R13)
   38 [-]: LOADK     R12 K11      ; R12 := "openssl "
   39 [-]: MOVE      R13 R3       ; R13 := R3
   40 [-]: LOADK     R14 K12      ; R14 := " -d %s %s | openssl zlib -d"
   41 [-]: CONCAT    R12 R12 R14  ; R12 := concat(R12 to R14)
   42 [-]: LOADK     R13 K11      ; R13 := "openssl "
   43 [-]: MOVE      R14 R3       ; R14 := R3
   44 [-]: LOADK     R15 K13      ; R15 := " -e %s %s"
   45 [-]: CONCAT    R13 R13 R15  ; R13 := concat(R13 to R15)
   46 [-]: LOADK     R14 K11      ; R14 := "openssl "
   47 [-]: MOVE      R15 R3       ; R15 := R3
   48 [-]: LOADK     R16 K14      ; R16 := " -d %s %s"
   49 [-]: CONCAT    R14 R14 R16  ; R14 := concat(R14 to R16)
   50 [-]: LOADK     R15 K18      ; R15 := "2EB38F7EC41D4B8E1422805BCD5F740BC3B95BE163E39D67579EB344427F7836"
   51 [-]: LOADK     R16 K19      ; R16 := "360028C9064242F81074F4C127D299F6"
   52 [-]: LOADK     R17 K20      ; R17 := "-K "
   53 [-]: MOVE      R18 R15      ; R18 := R15
   54 [-]: LOADK     R19 K21      ; R19 := " -iv "
   55 [-]: MOVE      R20 R16      ; R20 := R16
```

From this we can pull lots of information:
- Data is compressed with zlib and encrypted with AES-256-CBC
- `"2EB38F7EC41D4B8E1422805BCD5F740BC3B95BE163E39D67579EB344427F7836"` is passed as the key (-K)
- `"360028C9064242F81074F4C127D299F6"` is passed as the iv (-iv)
- A key file may be used if it exists (it doesn't)

This allows us to decrypt the encrypted config downloadable from the web interface. 

For some reason, the config is actually compressed, encrypted then compressed and encrypted again, so we just need to repeat the steps twice (and remove the md5).

Methods:
1. [Decrypting with CyberChef](https://gchq.github.io/CyberChef/#recipe=AES_Decrypt(%7B'option':'Hex','string':'2EB38F7EC41D4B8E1422805BCD5F740BC3B95BE163E39D67579EB344427F7836'%7D,%7B'option':'Hex','string':'360028C9064242F81074F4C127D299F6'%7D,'CBC','Raw','Raw',%7B'option':'Hex','string':''%7D,%7B'option':'Hex','string':''%7D)Zlib_Inflate(0,0,'Adaptive',false,false)Drop_bytes(0,16,false)AES_Decrypt(%7B'option':'Hex','string':'2EB38F7EC41D4B8E1422805BCD5F740BC3B95BE163E39D67579EB344427F7836'%7D,%7B'option':'Hex','string':'360028C9064242F81074F4C127D299F6'%7D,'CBC','Raw','Raw',%7B'option':'Hex','string':''%7D,%7B'option':'Hex','string':''%7D)Zlib_Inflate(0,0,'Adaptive',false,false))
2. Decrypting with openssl, b64, dd and python
```sh
KEY_HEX="2EB38F7EC41D4B8E1422805BCD5F740BC3B95BE163E39D67579EB344427F7836"
IV_HEX="360028C9064242F81074F4C127D299F6"

cat config.bin | \
openssl enc -d -aes-256-cbc -K "$KEY_HEX" -iv "$IV_HEX" -nopad | \
python3 -c 'import sys, zlib; sys.stdout.buffer.write(zlib.decompress(sys.stdin.buffer.read()))' | \
dd bs=1 skip=16 status=none | \
openssl enc -d -aes-256-cbc -K "$KEY_HEX" -iv "$IV_HEX" -nopad | \
python3 -c 'import sys, zlib; sys.stdout.buffer.write(zlib.decompress(sys.stdin.buffer.read()))'
```
3. Decrypting with re300 tool
	1. Clone this repo
		`git clone https://github.com/nullstring1/re300`
	2. Build tool
		`cargo build --release`
	3. Decrypt
		`./target/release/re300 decryptconfig --output config.xml config.bin`

### Modifying and encrypting config.xml
Once you've decrypted the config, you can modify it to change any setting, enable SSH and more.

#### Enabling SSH
To enable SSH, locate this section
```xml
<dropbear>
<dropbear>
<RootPasswordAuth>on</RootPasswordAuth>
<Port>22</Port>
<SysAccountLogin>off</SysAccountLogin>
<PasswordAuth>on</PasswordAuth>
</dropbear>
</dropbear>
```
and insert the following line
```xml
<RemoteSSH>on</RemoteSSH>
```
to create 
```xml
<dropbear>
<dropbear>
<RootPasswordAuth>on</RootPasswordAuth>
<Port>22</Port>
<SysAccountLogin>off</SysAccountLogin>
<PasswordAuth>on</PasswordAuth>
<RemoteSSH>on</RemoteSSH>
</dropbear>
</dropbear>
```

This should allow you to ssh into the device using the following command
```sh
ssh -o KexAlgorithms=+diffie-hellman-group1-sha1 -o HostKeyAlgorithms=+ssh-rsa admin@{router-ip-here}
```
The password should be your web interface password (not your TP-Link cloud password! You may need to reset the device if you previously setup to use the TP-Link cloud login!). 

If this fails, try:
- username as root
- executing a remote command if tty spawn fails
```sh
ssh -o KexAlgorithms=+diffie-hellman-group1-sha1 -o HostKeyAlgorithms=+ssh-rsa admin@{router-ip-here} -o RemoteCommand="ash"
```

#### Re-encrypting the config.xml after modifications
Methods:
1. [Encrypting with CyberChef](https://gchq.github.io/CyberChef/#recipe=Zlib_Deflate('Dynamic%20Huffman%20Coding')AES_Encrypt(%7B'option':'Hex','string':'2EB38F7EC41D4B8E1422805BCD5F740BC3B95BE163E39D67579EB344427F7836'%7D,%7B'option':'Hex','string':'360028C9064242F81074F4C127D299F6'%7D,'CBC','Raw','Raw',%7B'option':'Hex','string':''%7D)Pad_lines('Start',16,'%20%5C%5Cc8%5C%5Ce6%5C%5Cad%5C%5Cbc%5C%5C92%5C%5C7d%5C%5Cf0%5C%5C5f%5C%5Cb9%5C%5Cbf%5C%5Cdb%5C%5C54%5C%5C75%5C%5Cf2%5C%5C7c%5C%5Ca6')Zlib_Deflate('Dynamic%20Huffman%20Coding')AES_Encrypt(%7B'option':'Hex','string':'2EB38F7EC41D4B8E1422805BCD5F740BC3B95BE163E39D67579EB344427F7836'%7D,%7B'option':'Hex','string':'360028C9064242F81074F4C127D299F6'%7D,'CBC','Raw','Raw',%7B'option':'Hex','string':''%7D))
2. Encrypting with openssl, cat, cut, xxd, md5sum, printf and python
```sh
KEY_HEX="2EB38F7EC41D4B8E1422805BCD5F740BC3B95BE163E39D67579EB344427F7836"
IV_HEX="360028C9064242F81074F4C127D299F6"

input_file="config.xml"
output_file="config.bin"

cat <(printf "RE300" | md5sum | cut -d ' ' -f 1 | xxd -r -p) \
    <(cat "$input_file" | \
      python3 -c 'import sys, zlib; sys.stdout.buffer.write(zlib.compress(sys.stdin.buffer.read()))' | \
      openssl enc -aes-256-cbc -K "$KEY_HEX" -iv "$IV_HEX") | \
python3 -c 'import sys, zlib; sys.stdout.buffer.write(zlib.compress(sys.stdin.buffer.read()))' | \
openssl enc -aes-256-cbc -K "$KEY_HEX" -iv "$IV_HEX" -out "$output_file"```
3. Decrypting with re300 tool
	1. Clone this repo
		`git clone https://github.com/nullstring1/re300`
	2. Build tool
		`cargo build --release`
	3. Decrypt
		`./target/release/re300 encryptconfig --output config.bin config.xml`

Then you can upload the generated config.bin back to the web interface to apply your changes

## Building OpenWRT for RE300 and for direct flash programmning

### Building OpenWRT
1. Clone OpenWRT fork with RE300 support
    `git clone https://github.com/NullString1/openwrt`
2. Switch to `add-re300` branch
	`git switch add-re300`
3. Install dependencies
	e.g. with nix flake
```Nix
{
  description = "Rust Dev Env";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { nixpkgs, rust-overlay, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };
        pkgsCrossMipsel = pkgs.pkgsCross.mipsel-linux-gnu;
      in with pkgs; {
        devShells.default = mkShell rec {
          hardeningDisable = [ "all" ];
          buildInputs = [
            # Rust
            (rust-bin.stable.latest.default.override {
              extensions = ["rust-std" "rust-src"];
            })
            pkgsCrossMipsel.stdenv.cc
            pkgsCrossMipsel.openssl.dev
            rust-analyzer
            binwalk
            flashrom
            fontconfig.dev
            pkg-config
            squashfsTools
            ncurses
            ncurses.dev

          ];
          PKG_CONFIG_PATH = "${fontconfig.dev}/bin";
          LD_LIBRARY_PATH = "${lib.makeLibraryPath buildInputs}";
          shellHook = ''
            alias openwrt-build='make defconfig download clean world -j8'
          '';
        };
      });
}
```
4. Activate flake
	`nix develop`
5. Copy re300.config to .config
	`cp re300.config .config`
6. Build openwrt
	`openwrt-build` or `make defconfig download clean world -j$(nproc)`
7. Use `openwrt/bin/targets/ramips/mt76x8/openwrt-ramips-mt76x8-tplink_re300-v1-squashfs-kernel.bin` and `openwrt/bin/targets/ramips/mt76x8/openwrt-ramips-mt76x8-tplink_re300-v1-squashfs-rootfs.bin`

### Modding and building u-boot
1. Clone u-boot
	`git clone https://source.denx.de/u-boot/u-boot.git`
2. Modify `drivers/mtd/spi/spi-nor-ids.c` to add support for `EN25QH64A`
	1. Download patch from [https://gist.github.com/NullString1/433d487b59606f03ed4baf20d37452eb]()
	2. Apply patch to u-boot
		`git apply 0001-mtd-spi-nor-ids-Add-support-for-EON-en25qh64a.patch`
3. Create re300.conf 
	1. Download premade config from (https://gist.github.com/NullString1/d25229ce6c386d54b98a13a3d693be5e)[]
	2. Copy to `.config`
		`cp re300.conf .config`
4. Build u-boot
	`make -j$(nproc)`
5. Use `u-boot-with-spl.bin` 

### Building the flashable image
The flash needs to contain u-boot (specifically `u-boot-with-spl.bin`), openwrt kernel and the openwrt root filesystem. 

The `target/linux/ramips/dts/mt7628an_tplink_re300-v1.dts` file describes the flash layout I have configured OpenWrt to expect. You can change the sizes and offsets of partitions if you need so. 

| offset   | size     | name       |
| -------- | -------- | ---------- |
| 0        | 0x30000  | u-boot     |
| 0x30000  | 0x10000  | u-boot-env |
| 0x40000  | 0x2a0000 | kernel     |
| 0x2e0000 | 0x510000 | rootfs     |
| 0x7f0000 | 0x10000  | radio      |
#### Using re300 tool (Recommended)
1. Clone repo 
	`git clone https://github.com/nullstring1/re300`
2. Build in release mode
	`cargo build --release`
3. Build flash image using `buildseperate`
```sh 
./target/release/re300 buildseparate u-boot-with-spl.bin openwrt/bin/targets/ramips/mt76x8/openwrt-ramips-mt76x8-tplink_re300-v1-squashfs-kernel.bin openwrt/bin/targets/ramips/mt76x8/openwrt-ramips-mt76x8-tplink_re300-v1-squashfs-rootfs.bin
```

#### Using dd
Ensure that:
- `u-boot-with-spl.bin` is no larger than 0x30000 (196608) bytes or ~196KB
- `squashfs-kernel.bin` is no larger than 0x2a0000 (2752512) bytes or ~2.7MB
- `squashfs-rootfs.bin` is no larger than 0x510000 (5308416) bytes or ~5.3MB

1. Create 8MB image
	`dd if=/dev/zero of=new_flash_image.bin bs=1M count=8`
2. Add `u-boot-with-spl.bin`
	`dd if=u-boot-with-spl.bin of=new_flash_image.bin conv=notrunc`
3. Add `squashfs-kernel.bin` (skipping to 0x40000=262144 to leave 0x10000 for u-boot-env)
	`dd if=squashfs-kernel.bin of=new_flash_image.bin seek=262144 conv=notrunc`
4. Add `squashfs-rootfs.bin`
	`dd if=squashfs-rootfs.bin of=new_flash_image.bin seek=3014656 conv=notrunc`
5. Carve radio partition from flash dump
	`dd if=flash_dump.bin of=radio_part.bin skip=8323072 bs=1 count=65536`
6. Add radio partition to image
	`dd if=radio_part.bin of=new_flash_image.bin seek=8323072 bs=1 count=65536`

### Flashing
View [[#Dumping flash]] for setup instructions

**_NOTE: IT IS ABSOLUTELY RECOMMENDED THAT YOU DUMP YOUR FLASH BEFORE WRITING ANYTHING. THIS WILL SAVE YOUR DEVICE IN CASE YOU BRICK IT_**

Run the following, substituting in the programmer name, chip name and name of your flash image
```sh
flashrom -p {programmer_name} -c {chip_name} --write {flash_image.bin}
# eg. 
flashrom -p ch341a_spi -c en25qh64a --write complete_flash_seperate.bin
```

#### Booting
Once you have flashed the image, you will be ready to boot. However, as we did not setup u-boot-env or give u-boot a default command, you will need to do this in the u-boot shell.

1. Connect to serial as explained above in [[#Connecting serial]]
2. U-boot will complain about bad crc and will dump you into the u-boot shell
3. (Optional) Run the following to check image was built correctly and u-boot understands it. You should see details of the image and kernel printed. 
```sh
iminfo 0x40000
```
4. Run the following to setup u-boot to boot the image automatically, then boot
```sh
setenv bootcmd bootm 0x40000
saveenv
bootd # or run `reset` or manually power cycle
```
5. If you have done everything correctly, you should see the kernel boot log and eventually the line `Please press Enter to activate this console.`
6. You now have OpenWRT installed! Proceed by connecting the re300 to your AP following the instructions at [https://openwrt.org/docs/guide-user/network/wifi/connect_client_wifi#command-line_instructions]() (Ensure you set country code as this may prevent connections if left blank)
7. (Optional) Install luci
```sh
opkg install luci
```
