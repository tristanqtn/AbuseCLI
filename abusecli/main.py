import sys

from .parser import create_parser
from .auth import load_api_key
from .commands import cmd_check, cmd_report, cmd_load, cmd_categories
from .display import print_error


def main() -> None:
    parser = create_parser()

    if len(sys.argv) == 1:
        parser.print_help()
        return

    args = parser.parse_args()

    if args.command == "check":
        if not getattr(args, "ips", None) and not getattr(args, "from_file", None):
            print_error("check requires --ips, --from-file, or both")
            return

        try:
            api_key = load_api_key(args)
        except KeyboardInterrupt:
            print_error("Aborted.")
            return
        except SystemExit:
            raise
        except Exception as e:
            print_error(f"Failed to load API key: {e}")
            return

        cmd_check(args, api_key)

    elif args.command == "report":
        has_ips = getattr(args, "ips", None)
        has_file = getattr(args, "from_file", None)
        has_source = getattr(args, "source", None)

        if not has_ips and not has_file and not has_source:
            print_error("report requires --ips, --from-file, or --source")
            return

        if has_source and (has_ips or has_file):
            print_error("--source cannot be combined with --ips or --from-file")
            return

        try:
            api_key = load_api_key(args)
        except KeyboardInterrupt:
            print_error("Aborted.")
            return
        except SystemExit:
            raise
        except Exception as e:
            print_error(f"Failed to load API key: {e}")
            return

        cmd_report(args, api_key)

    elif args.command == "load":
        cmd_load(args)

    elif args.command == "categories":
        cmd_categories()

    else:
        parser.print_help()