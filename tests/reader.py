"""Establish a Unix socket connection."""

import argparse
import asyncio
import pathlib
import sys

async def main() -> None:
    """Main program: parse arguments, receive and send messages."""
    parser = argparse.ArgumentParser()
    parser.add_argument("pos_arg", type=pathlib.Path)
    args = parser.parse_args()
    try:
        reader, writer = await asyncio.open_unix_connection(args.pos_arg)
        line = await reader.readline()
        print(line.decode("UTF-8"), end='', flush=True)
        for line in sys.stdin:
            writer.write(line.encode("UTF-8"))
            await writer.drain()

    except Exception as err:
        print(f"Child error: {err}", file=sys.stderr)
        raise

if __name__ == "__main__":
    asyncio.run(main())
