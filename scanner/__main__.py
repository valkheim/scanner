import argparse
import sys

import scanner.cli
import scanner.gui


def get_arguments() -> argparse.Namespace:
    """Parse CLI options"""
    parser = argparse.ArgumentParser()
    subs = parser.add_subparsers()

    gui_parser = subs.add_parser("gui")
    gui_parser.set_defaults(run=scanner.gui.run)

    cli_parser = subs.add_parser("cli")
    cli_parser.set_defaults(run=scanner.cli.run)
    cli_parser.add_argument("--file")

    return parser.parse_args()


def main():
    args = get_arguments()
    return args.run(args)


if __name__ == "__main__":
    sys.exit(main())
