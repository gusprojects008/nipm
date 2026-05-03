from dataclasses import dataclass
from cli_core.deps import check_dependencies

@dataclass
class BootstrapResult:
    context: object
    operations: object

def init(config: dict) -> BootstrapResult:
    MODULE_DEPENDENCIES = config.get("module_dependencies")
    SYSTEM_DEPENDENCIES = config.get("system_dependencies")

    check_dependencies(MODULE_DEPENDENCIES, SYSTEM_DEPENDENCIES)

    from cli_core.log import setup_logging, build_logging_config

    if config.get("argparse"):
        args = config.get("argparse").get("args")
        logging_config = build_logging_config(args.verbose, args.output)
        log_filepath = str(setup_logging(logging_config=logging_config))
    else:
        log_filepath = str(setup_logging(verbose=True, output_fullpath="nipm-debug.log"))

    from core.context import AppContext
    from core.app import Operations

    config["log_filepath"] = log_filepath

    context = AppContext(config)
    operations = Operations(context)

    return BootstrapResult(context, operations)
