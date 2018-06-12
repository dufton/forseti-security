# Copyright 2018 The Forseti Security Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Stackdriver Logging Log Sink rules engine.

Builds the RuleBook (LogSinkRuleBook) from the rule definitions (file either
stored locally or in GCS) and compares a resource's log sinks against the
RuleBook to determine whether there are violations.
"""

import collections
import itertools
import threading

from google.cloud.forseti.common.gcp_type import resource_util
from google.cloud.forseti.common.gcp_type.iam_policy import IamAuditConfig
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.common.util import relationship
from google.cloud.forseti.scanner.audit import base_rules_engine as bre
from google.cloud.forseti.scanner.audit import errors as audit_errors

LOGGER = logger.get_logger(__name__)

VIOLATION_TYPE = 'LOG_SINK_VIOLATION'


class LogSinkRulesEngine(bre.BaseRulesEngine):
    """Rules engine for Log Sinks."""

    def __init__(self, rules_file_path, snapshot_timestamp=None):
        """Initialize.

        Args:
            rules_file_path (str): File location of rules.
            snapshot_timestamp (str): The snapshot to work with.
        """
        super(LogSinkRulesEngine, self).__init__(
            rules_file_path=rules_file_path,
            snapshot_timestamp=snapshot_timestamp)
        self.rule_book = None

    def build_rule_book(self, global_configs=None):
        """Build LogSinkRuleBook from the rules definition file.

        Args:
            global_configs (dict): Global configurations.
        """
        self.rule_book = LogSinkRuleBook(
            global_configs,
            self._load_rule_definitions(),
            snapshot_timestamp=self.snapshot_timestamp)

    def find_violations(self, resource, log_sinks, force_rebuild=False):
        """Determine whether a resource's log sinks violate rules.

        Args:
            resource (gcp_type): The resource the log sinks belong to.
            log_sinks (list): List of Log Sinks for resource.
            force_rebuild (bool): If True, rebuilds the rule book.
                This will reload the rules definition file and add the
                rules to the book.

        Returns:
            iterable: A generator of rule violations.
        """
        if self.rule_book is None or force_rebuild:
            self.build_rule_book()

        violations = self.rule_book.find_violations(resource, log_sinks)

        return set(violations)

    def add_rules(self, rules):
        """Add rules to the rule book.

        Args:
            rules (list): The list of rules to add to the book.
        """
        if self.rule_book is not None:
            self.rule_book.add_rules(rules)


class LogSinkRuleBook(bre.BaseRuleBook):
    """The RuleBook for Log Sink configs.

    Rules from the rules definition file are parsed and placed into a map, which
    associates the GCP resource (project, folder or organization) with the
    rules defined for it.

    TODO(): MORE DETAILS
    """

    supported_resource_types = frozenset([
        'project',
        'folder',
        'organization',
    ])

    def __init__(self,
                 global_configs,  # pylint: disable= unused-argument
                 rule_defs=None,
                 snapshot_timestamp=None):
        """Initialize.

        Args:
            global_configs (dict): Global configurations.
            rule_defs (dict): The parsed dictionary of rules from the YAML
                definition file.
            snapshot_timestamp (str): The snapshot to lookup data.
        """
        super(LogSinkRuleBook, self).__init__()
        self._rules_sema = threading.BoundedSemaphore(value=1)
        self.resource_rules_map = collections.defaultdict(set)
        if not rule_defs:
            self.rule_defs = {}
        else:
            self.rule_defs = rule_defs
            self.add_rules(rule_defs)
        if snapshot_timestamp:
            self.snapshot_timestamp = snapshot_timestamp

    def __eq__(self, other):
        """Equals.

        Args:
            other (object): Object to compare.

        Returns:
            bool: True or False.
        """
        if not isinstance(other, type(self)):
            return NotImplemented
        return self.resource_rules_map == other.resource_rules_map

    def __ne__(self, other):
        """Not Equals.

        Args:
            other (object): Object to compare.

        Returns:
            bool: True or False.
        """
        return not self == other

    def __repr__(self):
        """Object representation.

        Returns:
            str: The object representation.
        """
        return 'LogSinkRuleBook <{}>'.format(self.resource_rules_map)

    def add_rules(self, rule_defs):
        """Add rules to the rule book.

        Args:
            rule_defs (dict): Rules parsed from the rule definition file.
        """
        for (i, rule) in enumerate(rule_defs.get('rules', [])):
            self.add_rule(rule, i)

    def add_rule(self, rule_def, rule_index):
        """Add a rule to the rule book.

        The rule supplied to this method is the dictionary parsed from
        the rules definition file.

        For example, this rule...

        TODO() UPDATE DETAILS

            # rules yaml:
            rules:

        ... gets parsed into:

            {
            }

        Args:
            rule_def (dict): Contains rule definition properties.
            rule_index (int): The index of the rule from the rule definitions.
                Assigned automatically when the rule book is built.
        """
        self._rules_sema.acquire()

        try:
            resources = rule_def.get('resource')

            # TODO() ADD RULE PARSING

        finally:
            self._rules_sema.release()

    def find_violations(self, resource, log_sinks):
        """Find Log Sink violations in the rule book.

        Args:
            resource (gcp_type): The resource the log sinks belong to.
            log_sinks (list): List of Log Sinks for resource.

        Returns:
            iterable: A generator of the rule violations.
        """
        violations = itertools.chain()

        # TODO() IMPLEMENT

        return violations


class Rule(object):
    """Rule properties from the rule definition file. Also finds violations."""

    RuleViolation = collections.namedtuple(
        'RuleViolation',
        ['resource_type', 'resource_id', 'full_name', 'rule_name', 'rule_index',
         'violation_type', 'log_sink_name', 'resource_data'])

    def __init__(self, rule_name, rule_index, rule):
        """Initialize.
        Args:
            rule_name (str): Name of the loaded rule.
            rule_index (int): The index of the rule from the rule definitions.
            rule (dict): The rule definition from the file.
        """
        self.rule_name = rule_name
        self.rule_index = rule_index
        self.rule = rule

    def find_violations(self, resource, log_sinks):
        """Find Log Sink violations in the rule book.
        Args:
            resource (gcp_type): The resource the log sinks belong to.
            log_sinks (list): List of Log Sinks for resource.
        Yields:
            namedtuple: Returns RuleViolation named tuple.
        """
        # TODO() IMPLEMENT
        pass
