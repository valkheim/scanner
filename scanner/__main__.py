import argparse
import sys

import scanner.cli
import scanner.gui


def get_arguments() -> argparse.Namespace:
    """Parse CLI options"""
    parser = argparse.ArgumentParser()
    parser.add_argument("--gui", action="store_true")
    parser.add_argument("--last", action="store_true")
    parser.add_argument("--file")
    return parser.parse_args()


def main():
    args = get_arguments()
    if args.gui:
        return scanner.gui.run(args)

    return scanner.cli.run(args)


if __name__ == "__main__":
    sys.exit(main())
