# This dnf plugin captures various timing metrics emitted by the loggers
# from within the dnf codebase, associates transaction details, and then
# serializes the timing record into a json file in /var/log/dnf/perfmetrics.
#
# Timing metrics are collected from logging messages to the logger object
# at DEBUG level with "timer: .*: \d+ ms" in the message.
#
# For example, from base `dnf` code:
#   timer = dnf.logging.Timer("depsolve")
#   ... (actually do depsolve here) ...
#   timer()

import json
import logging
import os
import re
import sys
import time

from psutil import Process

import dnf
import dnf.logging


DEFAULT_METRICS_DIR = "/var/log/dnf/perfmetrics"
DEFAULT_RETENTION_HOURS = 4


LOGGER = logging.getLogger("dnf")


class MetricsFilter(logging.Filter):
    """Logging Filter being abused into storing timing metrics records."""

    # Regular expression matching the output format of logging.Timer.
    TIME_PATTERN = re.compile(r"^timer: (?P<event>.*): (?P<millisecs>[0-9.]+) ms$")

    def __init__(self, metrics_dict):
        # Where to store the timing metrics.
        self.metrics_dict = metrics_dict

    def filter(self, record):
        m = self.TIME_PATTERN.fullmatch(str(record.msg))
        if m:
            k = "{}_time".format(m.group("event").replace(" ", "_"))
            self.metrics_dict[k] = int(m.group("millisecs"))
        # Always return False, to filter out every record from the logs.
        return False


class DnfPerfMetrics(dnf.Plugin):
    """Dnf plug-in to record timing metrics of Dnf invocations."""

    name = "perfmetrics"

    def __init__(self, base, cli):
        super().__init__(base, cli)
        self.base = base
        self.cli = cli
        self.time_metrics = {}

        # Install the MetricsFilter logger. Hook our handler to all of the
        # relevant loggers which emit metrics and perf messages.
        #
        # See: https://dnf.readthedocs.io/en/latest/api_common.html
        metrics_handler = logging.StreamHandler(sys.stderr)
        metrics_handler.setLevel(dnf.logging.DDEBUG)
        metrics_handler.addFilter(MetricsFilter(self.time_metrics))
        LOGGER.addHandler(metrics_handler)

        # Starts a timer for capturing the full command duration.
        self.full_command_start_time = time.time()

        # Store the process tree and command-line arguments. The process tree
        # includes the parents of the DNF process all the way to init. It can
        # be used to detect whether DNF was launched by a host agent, or just
        # run manually from a user session.
        proc = Process()
        self.time_metrics["process_tree"] = list(
            reversed([proc.name()] + [p.name() for p in proc.parents()])
        )
        self.time_metrics["command_args"] = sys.argv

        # Set defaults for config variables. We default to saving the
        # perfmetrics reports to `/var/log/yum` since that is where our Chef
        # handler expects to collect them.
        self.metrics_dir = DEFAULT_METRICS_DIR
        self.retention_hours = DEFAULT_RETENTION_HOURS

    def config(self):
        cp = self.read_config(self.base.conf)
        if cp.has_section("main"):
            if cp.has_option("main", "metrics_dir"):
                self.metrics_dir = cp.get("main", "metrics_dir")
            if cp.has_option("main", "retention_hours"):
                self.retention_hours = int(cp.get("main", "retention_hours"))

    def pre_transaction(self):
        # Pull transaction details for logging with the timing metrics.
        package_actions = []
        for member in self.base.transaction:
            package_actions.append(
                {
                    "name": member.name,
                    "arch": member.arch,
                    "epoch": member.epoch,
                    "version": member.version,
                    "release": member.release,
                    "action": member.action_short,
                    "package_size": member.pkg.size,
                    "install_size": member.pkg.installsize,
                }
            )
        self.transaction_start_time = time.time()
        self.time_metrics["package_actions"] = package_actions

    def transaction(self):
        # Finish timer for the transaction phase, close pending timers,
        # serialize the captured metrics, clean up.
        self.time_metrics["full_transaction_time"] = int(
            (time.time() - self.transaction_start_time) * 1000
        )

        # If we're not root, we can't write the logs or cleanup
        if os.geteuid() != 0:
            return

        self.write_results()
        self.cleanup_old_logs()

    def write_results(self):
        # Write out the transaction results to a JSON file.
        now = time.time()
        metrics_dir = self.metrics_dir
        if not os.path.exists(metrics_dir):
            os.makedirs(metrics_dir)

        filename = os.path.join(
            metrics_dir, "perfmetrics-{}_{}.json".format(now, os.getpid())
        )
        try:
            with open(filename, "w") as fh:
                json.dump(self.time_metrics, fh, indent=2)
                fh.write("\n")
        except (IOError, OSError) as e:
            LOGGER.error(
                "Error writing performance metrics to file %s", filename, exc_info=True
            )

    def cleanup_old_logs(self):
        # Clean up perfmetrics files over a week old.
        now = time.time()
        metrics_dir = self.metrics_dir
        retention_hours = self.retention_hours
        for f in os.listdir(metrics_dir):
            f = os.path.join(metrics_dir, f)
            if os.stat(f).st_mtime < now - retention_hours * 3600:
                os.remove(f)
