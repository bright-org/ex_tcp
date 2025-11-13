#!/usr/bin/env python3
import fcntl, os, struct, sys, select

TUNSETIFF = 0x400454ca
IFF_TAP   = 0x0002
IFF_NO_PI = 0x1000

def open_tap(name="tap0"):
    fd = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack("16sH", name.encode(), IFF_TAP | IFF_NO_PI)
    fcntl.ioctl(fd, TUNSETIFF, ifr)
    return fd

def main():
    tap = open_tap(sys.argv[1] if len(sys.argv) > 1 else "tap0")

    while True:
        r, _, _ = select.select([tap, sys.stdin.buffer], [], [])
        if sys.stdin.buffer in r:
            out = os.read(sys.stdin.fileno(), 4096)
            if not out:
                break
            os.write(tap, out)
            
        if tap in r:
            data = os.read(tap, 4096)
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()

if __name__ == "__main__":
    main()
