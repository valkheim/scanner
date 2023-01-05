import argparse
import sys

import scanner.classify
import scanner.cli
import scanner.gui


def get_arguments() -> argparse.Namespace:
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

    cli_parser = subs.add_parser("classify")
    cli_parser.set_defaults(run=scanner.classify.run)
    cli_parser.add_argument(
        "--output_dir", help="Directory path where production will be stored"
    )
    cli_parser.add_argument(
        "--malwares_dir", help="Directory path of the malware samples"
    )
    cli_parser.add_argument(
        "--benigns_dir", help="Directory path of the benignware samples"
    )
    cli_parser.add_argument(
        "--scatter_matrix",
        action="store_true",
        help="Generate a scatter matrix of the analysis features",
    )
    cli_parser.add_argument(
        "--correlation_matrix",
        action="store_true",
        help="Generate a correlation matrix of the analysis features",
    )

    cli_parser.add_argument(
        "--classifier_path",
        help="Path of the serialized classifier to use (e.g. /tmp/random_forest.joblib",
    )
    cli_parser.add_argument(
        "--test_file", help="Predict the software class of a file by path"
    )
    cli_parser.add_argument(
        "--test_dir",
        help="Predict the software class of files within a directory by path",
    )

    cli_parser.add_argument("--dry", help="Test features")

    return parser, parser.parse_args()


def main():
    parser, args = get_arguments()
    if not hasattr(args, "run"):
        parser.print_help()
        return 2

    return args.run(args)


if __name__ == "__main__":
    sys.exit(main())
