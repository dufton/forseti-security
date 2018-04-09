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

"""Cloud Audit Logging rules engine for organizations, folders, and projects.

Builds the RuleBook (AuditLoggingRuleBook) from the rule definitions (file
either stored locally or in GCS) and compares a dictionary of enabled audit logs
against the RuleBook to determine whether there are violations.
"""

import collections
import itertools
import threading

from google.cloud.forseti.common.gcp_type import errors as resource_errors
from google.cloud.forseti.common.gcp_type import resource as resource_mod
from google.cloud.forseti.common.gcp_type import resource_util
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.common.util import relationship
from google.cloud.forseti.scanner.audit import base_rules_engine as bre
from google.cloud.forseti.scanner.audit import errors as audit_errors

LOGGER = logger.get_logger(__name__)


class AuditLoggingRulesEngine(bre.BaseRulesEngine):
    """Rules engine for Cloud Audit Logging."""

    def __init__(self, rules_file_path, snapshot_timestamp=None):
        """Initialize.

        Args:
            rules_file_path (str): File location of rules.
            snapshot_timestamp (str): The snapshot to work with.
        """
        super(AuditLoggingRulesEngine, self).__init__(
            rules_file_path=rules_file_path,
            snapshot_timestamp=snapshot_timestamp)
        self.rule_book = None

    def build_rule_book(self, global_configs=None):
        """Build AuditLoggingRuleBook from the rules definition file.

        Args:
            global_configs (dict): Global configurations.
        """
        self.rule_book = AuditLoggingRuleBook(
            global_configs,
            self._load_rule_definitions(),
            snapshot_timestamp=self.snapshot_timestamp)

    def find_policy_violations(self, project, project_config,
                               force_rebuild=False):
        """Determine whether a projects audit logging config violates rules.

        Args:
            project (gcp_type): The project with audit log config.
            project_config (dict): Audit logs config for this project.
            force_rebuild (bool): If True, rebuilds the rule book.
                This will reload the rules definition file and add the
                rules to the book.

        Returns:
            iterable: A generator of rule violations.
        """
        if self.rule_book is None or force_rebuild:
            self.build_rule_book()

        violations = self.rule_book.find_violations(project, project_config)

        return set(violations)

    def add_rules(self, rules):
        """Add rules to the rule book.

        Args:
            rules (list): The list of rules to add to the book.
        """
        if self.rule_book is not None:
            self.rule_book.add_rules(rules)


class AuditLoggingRuleBook(bre.BaseRuleBook):
    """The RuleBook for Audit Logging configs.

    TODO
    """

    def __init__(self,
                 # TODO: To remove the unused global-configs here, it will be
                 # necessary to also update the base rules engine.
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
        super(AuditLoggingRuleBook, self).__init__()
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
        return 'AuditLoggingRuleBook <{}>'.format(self.resource_rules_map)

    def add_rules(self, rule_defs):
        """Add rules to the rule book.

        Args:
            rule_defs (dict): Rules parsed from the rule definition file.
        """
        for (i, rule) in enumerate(rule_defs.get('rules', [])):
            self.add_rule(rule, i)

    def add_rule(self, rule_def, rule_index):
        """Add a rule to the rule book.

        TODO ----------------------------------------------------------------------------------
        The rule supplied to this method is the dictionary parsed from
        the rules definition file.

        For example, this rule...

            # rules yaml:
            rules:
              - name: a rule
                mode: whitelist
                resource:
                  - type: project
                    resource_ids:
                      - my-project-123
                services:
                  - 'compute.googleapis.com'
                  - 'storage-component.googleapis.com'
                  - 'storage-api.googleapis.com'

        ... gets parsed into:

            {
                'name': 'a rule',
                'mode': 'whitelist',
                'resource': {
                    'type': 'project',
                    'resource_ids': ['my-project-id']
                },
                'services': [
                    'compute.googleapis.com',
                    'storage-component.googleapis.com',
                    'storage-api.googleapis.com'
                ]
            }

        Args:
            rule_def (dict): Contains rule definition properties.
            rule_index (int): The index of the rule from the rule definitions.
                Assigned automatically when the rule book is built.
        """
        pass

    def find_violations(self, project, enabled_apis):
        """Find enabled apis violations in the rule book.

        Args:
            project (gcp_type): The project that these APIs are enabled on.
            enabled_apis (list): list of enabled APIs.

        Returns:
            iterable: A generator of the rule violations.
        """
        violations = itertools.chain()

        return violations


class Rule(object):
    """Rule properties from the rule definition file. Also finds violations."""

    RuleViolation = collections.namedtuple(
        'RuleViolation',
        ['resource_type', 'resource_id', 'full_name', 'rule_name', 'rule_index',
         'violation_type', 'apis', 'inventory_data'])

    def __init__(self, rule_name, rule_index, rules):
        """Initialize.
        Args:
            rule_name (str): Name of the loaded rule.
            rule_index (int): The index of the rule from the rule definitions.
            rules (dict): The rules from the file.
        """
        self.rule_name = rule_name
        self.rule_index = rule_index
        self.rules = rules

    # TODO: The naming is confusing and needs to be fixed in all scanners.
    def find_policy_violations(self, project, enabled_apis):
        """Find Enabled API violations in the rule book.
        Args:
            project (gcp_type): The project that these APIs are enabled on.
            enabled_apis (list): list of enabled APIs.
        Yields:
            namedtuple: Returns RuleViolation named tuple.
        """
        pass

