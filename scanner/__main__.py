import argparse
import sys

import scanner.classify
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
    cli_parser.add_argument("--dir")
    cli_parser.add_argument("--hash")
    cli_parser.add_argument("--last", action="store_true")

    cli_parser = subs.add_parser("classify")
    cli_parser.set_defaults(run=scanner.classify.run)
    cli_parser.add_argument("--malwares_dir")
    cli_parser.add_argument("--benigns_dir")

    return parser.parse_args()


def main():
    args = get_arguments()
    return args.run(args)


if __name__ == "__main__":
    sys.exit(main())
