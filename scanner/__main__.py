import argparse
import sys
import typing as T

import scanner.cli
import scanner.gui


def get_arguments() -> T.Tuple[argparse.ArgumentParser, argparse.Namespace]:
    """Parse CLI options"""
    parser = argparse.ArgumentParser()
    subs = parser.add_subparsers()

    gui_parser = subs.add_parser("gui", description="The scanner GUI mode")
    gui_parser.set_defaults(run=scanner.gui.run)

    cli_parser = subs.add_parser(
        "cli", description="The scanner command line mode"
    )
    cli_parser.set_defaults(run=scanner.cli.run)
    cli_parser.add_argument("--file", help="Scan a file by path")
    cli_parser.add_argument("--dir", help="Scan a directory by path")
    cli_parser.add_argument("--hash", help="Retrieve scan results by hash")
    cli_parser.add_argument(
        "--last", action="store_true", help="Retrieve the last analyzed files"
    )

    if not sys.argv[2:]:
        if sys.argv[1:] and sys.argv[1] == "cli":
            sys.argv.append("--help")

    return parser, parser.parse_args()


def main() -> T.Any:
    parser, args = get_arguments()
    if not hasattr(args, "run"):
        parser.print_help()
        return 2

    return args.run(args)


if __name__ == "__main__":
    sys.exit(main())
