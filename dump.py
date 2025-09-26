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
