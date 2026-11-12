import argparse
from pathlib import Path
import random

def generate_salt(seed: int, size: int, output: Path):
    generator = random.Random(seed)
    result = generator.randbytes(size)
    with output.open("wb") as f:
        f.write(result)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', default='input.txt')
    parser.add_argument('--seed', default=67)
    parser.add_argument('--size', default='16')

    args = parser.parse_args()

    allowed_size = {
        "Kb": 1024,
        "Mb": 1024 * 1024,
        "Gb": 1024 * 1024 * 1024
    }
    for size in allowed_size.keys():
        if args.size.endswith(size):
            args.size = int(args.size.rstrip(size)) * allowed_size[size]
            break
    else:
        args.size = int(args.size)

    generate_salt(args.seed, args.size, Path(args.output))

if __name__ == "__main__":
    main()
