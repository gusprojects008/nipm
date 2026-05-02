from dataclasses import dataclass
from cli_core.deps import check_dependencies
from cli_core.system import check_root


@dataclass
class BootstrapResult:
    log_filename: str
    context: object
    operations: object


def init(config: dict) -> BootstrapResult:
    MODULE_DEPENDENCIES = config.get("module_dependencies")
    SYSTEM_DEPENDENCIES = config.get("system_dependencies")
    args = config.get("args")

    check_dependencies(MODULE_DEPENDENCIES, SYSTEM_DEPENDENCIES)

    check_root()

    from cli_core.log import setup_logging, build_logging_config

    if args:
        logging_config = build_logging_config(args.verbose, getattr(args, "output", None))
        log_filename = str(setup_logging(logging_config=logging_config))
    else:
        log_filename = str(setup_logging(verbose=True, output_fullpath="nipm-test.log"))

    from core.context import AppContext
    from core.app import Operations

    context = AppContext()
    operations = Operations(context)

    return BootstrapResult(log_filename, context, operations)
