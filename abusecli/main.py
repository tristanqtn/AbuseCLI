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