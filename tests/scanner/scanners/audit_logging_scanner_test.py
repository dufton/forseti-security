# pylint: disable=bad-indentation
# disabled since Forseti code uses 4 space indentation


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
"""Tests for AuditLoggingScanner."""

from datetime import datetime
import json
import unittest
import mock

from tests.unittest_utils import ForsetiTestCase
from google.cloud.forseti.common.gcp_type import iam_policy
from google.cloud.forseti.common.gcp_type.bucket import Bucket
from google.cloud.forseti.common.gcp_type.folder import Folder
from google.cloud.forseti.common.gcp_type.organization import Organization
from google.cloud.forseti.common.gcp_type.project import Project
from google.cloud.forseti.common.util import string_formats
from google.cloud.forseti.scanner.scanners import audit_logging_scanner


class AuditLoggingScannerTest(ForsetiTestCase):

    @mock.patch(
        'google.cloud.forseti.scanner.scanners.audit_logging_scanner.audit_logging_rules_engine',
        autospec=True)
    def setUp(self, mock_rules_engine):

        self.fake_utcnow = datetime(
            year=1900, month=1, day=1, hour=0, minute=0, second=0,
            microsecond=0)

        self.scanner = audit_logging_scanner.AuditLoggingScanner(
            {}, {}, mock.MagicMock(), '', '', '')
        self._add_ancestor_audit_configs_test_data()

    def _make_mock_policy_resource(self, parent, audit_configs=None):
        """Create a mock IamPolicy resource."""
        pr = mock.MagicMock()
        name = '{}:{}'.format(parent.type, parent.id)
        pr.full_name = '{}/iam_policy/{}/'.format(parent.full_name, name)
        pr.type_name = 'iam_policy/{}'.format(name)
        pr.name = name
        pr.type = 'iam_policy'
        data_dict = {
            'bindings': [
                {
                    'role': 'roles/owner',
                    'members': ['user:someone@company.com']
                }
            ],
            'etag': 'BwVmQ+cRxiA=',
        }
        if audit_configs:
            data_dict['auditConfigs'] = audit_configs
        pr.data = json.dumps(data_dict)
        pr.parent = parent
        return pr

    def _add_ancestor_audit_configs_test_data(self):
        """Establishes the hierarchy below.
               +----------------------------> proj_1
               |
               |
               +
            org_234 +------> folder_1 +-----> proj_3
               |
               |
               |
               +----------------------------> proj_2 +-------> bucket_2_1
        """
        self.org_234 = Organization(
            '234',
            display_name='Organization 234',
            full_name='organization/234/',
            data='fake_org_data_234')
        audit_configs = [
            {
                'service': 'allServices',
                'auditLogConfigs': [
                    {
                        'logType': 'ADMIN_READ'
                    }
                ]
            }
        ]
        self.org_234_policy_resource = self._make_mock_policy_resource(
            parent=self.org_234, audit_configs=audit_configs)

        self.proj_1 = Project(
            'proj-1',
            project_number=22345,
            display_name='My project 1',
            parent=self.org_234,
            full_name='organization/234/project/proj-1/',
            data='fake_project_data_111')
        # Project 1 doesn't add any audit log configs.
        self.proj_1_policy_resource = self._make_mock_policy_resource(
            parent=self.proj_1, audit_configs=None)

        self.proj_2 = Project(
            'proj-2',
            project_number=22346,
            display_name='My project 2',
            parent=self.org_234,
            full_name='organization/234/project/proj-2/',
            data='fake_project_data_222')
        audit_configs = [
            {
                'service': 'allServices',
                'auditLogConfigs': [
                    {
                        'logType': 'ADMIN_READ'
                    },
                    {
                        'logType': 'DATA_WRITE'
                    }
                ]
            },
            {
                'service': 'cloudsql.googleapis.com',
                'auditLogConfigs': [
                    {
                        'logType': 'ADMIN_READ',
                        'exemptedMembers': [
                            'user1@org.com'
                        ]
                    },
                ]
            }
        ]
        self.proj_2_policy_resource = self._make_mock_policy_resource(
            parent=self.proj_2, audit_configs=audit_configs)


        self.folder_1 = Folder(
            '333',
            display_name='Folder 1',
            parent=self.org_234,
            full_name='organization/234/folder/333/',
            data='fake_folder_data_111')
        audit_configs = [
            {
                'service': 'allServices',
                'auditLogConfigs': [
                    {
                        'logType': 'ADMIN_READ',
                        'exemptedMembers': [
                            'user1@org.com',
                            'user2@org.com',
                        ]
                    },
                ]
            },
            {
                'service': 'cloudsql.googleapis.com',
                'auditLogConfigs': [
                    {
                        'logType': 'DATA_READ',
                    },
                    {
                        'logType': 'DATA_WRITE',
                    },
                ]
            }
        ]
        self.folder_1_policy_resource = self._make_mock_policy_resource(
            parent=self.folder_1, audit_configs=audit_configs)

        self.proj_3 = Project(
            'proj-3',
            project_number=22347,
            display_name='My project 3',
            parent=self.folder_1,
            full_name='organization/234/folder/333/project/proj-3/',
            data='fake_project_data_333')
        audit_configs = [
            {
                'service': 'allServices',
                'auditLogConfigs': [
                    {
                        'logType': 'ADMIN_READ',
                        'exemptedMembers': [
                            'user2@org.com',
                            'user3@org.com',
                        ]
                    },
                    {
                        'logType': 'DATA_READ',
                    },
                ]
            },
            {
                'service': 'compute.googleapis.com',
                'auditLogConfigs': [
                    {
                        'logType': 'DATA_READ',
                    },
                    {
                        'logType': 'DATA_WRITE',
                    },
                ]
            }
        ]
        self.proj_3_policy_resource = self._make_mock_policy_resource(
            parent=self.proj_3, audit_configs=audit_configs)

        # Buckets have IAM policies, but no audit configs.
        self.bucket_2_1 = Bucket(
            'internal-2',
            display_name='My project 2, internal data',
            parent=self.proj_2,
            full_name='organization/234/project/proj-2/bucket/internal-2/',
            data='fake_project_data_222_bucket_1')
        self.bucket_2_1_policy_resource = self._make_mock_policy_resource(
            parent=self.bucket_2_1)

    def testget_output_filename(self):
        """Test that the output filename of the scanner is correct.

        Expected:
            * Scanner output filename matches the format.
        """
        fake_utcnow_str = self.fake_utcnow.strftime(
            string_formats.TIMESTAMP_TIMEZONE_FILES)

        expected = string_formats.SCANNER_OUTPUT_CSV_FMT.format(fake_utcnow_str)
        actual = self.scanner.get_output_filename(self.fake_utcnow)
        self.assertEquals(expected, actual)

    @mock.patch.object(
        audit_logging_scanner.AuditLoggingScanner,
        '_output_results_to_db', autospec=True)
    @mock.patch.object(
        audit_logging_scanner.AuditLoggingScanner,
        '_flatten_violations')
    # autospec on staticmethod will return noncallable mock
    def test_output_results(
        self, mock_flatten_violations, mock_output_results_to_db):
        """Test _output_results() flattens / stores results."""
        self.scanner._output_results(None)

        self.assertEqual(1, mock_flatten_violations.call_count)
        self.assertEqual(1, mock_output_results_to_db.call_count)

    def test_retrieve_finds_audit_configs(self):
        """AuditLoggingScanner::_retrieve() finds audit log configurations.

        _retrieve() is picking up project audit log configs, saved in IAM
        policies and joining applicable folder and organization level configs.
        """
        policy_resources = [
            self.org_234_policy_resource,
            self.folder_1_policy_resource,
            self.proj_1_policy_resource,
            self.proj_2_policy_resource,
            self.proj_3_policy_resource,
            self.bucket_2_1_policy_resource
        ]

        mock_data_access = mock.MagicMock()
        mock_data_access.scanner_iter.return_value = policy_resources
        mock_service_config = mock.MagicMock()
        mock_service_config.model_manager = mock.MagicMock()
        mock_service_config.model_manager.get.return_value = (
            mock.MagicMock(), mock_data_access)
        self.scanner.service_config = mock_service_config

        # Call the method under test.
        audit_logging_data = self.scanner._retrieve()

        # Only projects are saved in the output.
        self.assertEqual(3, len(audit_logging_data))

        actual_configs = {project.full_name : config
                          for project, config in audit_logging_data}

        proj_1_config = {
            'allServices': {
                'ADMIN_READ': set()
            },
        }
        self.assertEqual(proj_1_config, actual_configs[self.proj_1.full_name])

        proj_2_config = {
            'allServices': {
                'ADMIN_READ': set(),
                'DATA_WRITE': set(),
            },
            'cloudsql.googleapis.com': {
                'ADMIN_READ': set(['user1@org.com']),
            },
        }
        self.assertEqual(proj_2_config, actual_configs[self.proj_2.full_name])

        proj_3_config = {
            'allServices': {
                'ADMIN_READ': set([
                    'user1@org.com',
                    'user2@org.com',
                    'user3@org.com'
                ]),
                'DATA_READ': set(),
            },
            'compute.googleapis.com': {
                'DATA_READ': set(),
                'DATA_WRITE': set(),
            },
            'cloudsql.googleapis.com': {
                'DATA_READ': set(),
                'DATA_WRITE': set(),
            },
        }
        self.assertEqual(proj_3_config, actual_configs[self.proj_3.full_name])


if __name__ == '__main__':
    unittest.main()

