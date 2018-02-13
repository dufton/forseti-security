# Copyright 2017 The Forseti Security Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

""" Forseti Installer"""

from __future__ import print_function
from abc import ABCMeta
from abc import abstractmethod

from util.utils import (
    print_banner, get_forseti_version, format_service_acct_id,
    infer_version)
from util.constants import (
    FORSETI_CONF_PATH, DEPLOYMENT_TEMPLATE_OUTPUT_PATH,
    MESSAGE_DEPLOYMENT_HAD_ISSUES, MESSAGE_DEPLOYMENT_TEMPLATE_LOCATION,
    MESSAGE_VIEW_DEPLOYMENT_DETAILS, MESSAGE_FORSETI_CONFIGURATION_GENERATED,
    MESSAGE_FORSETI_CONFIGURATION_GENERATED_DRY_RUN, DEFAULT_BUCKET_FMT,
    MESSAGE_FORSETI_BRANCH_DEPLOYED)
from util.gcloud import (
    create_reuse_service_acct, check_billing_enabled, lookup_organization,
    get_gcloud_info, verify_gcloud_information, create_deployment)
from util.files import (
    copy_file_to_destination, generate_deployment_templates,
    generate_forseti_conf)
from configs.config import Config


class ForsetiInstaller:
    """Forseti installer base class (abstract)"""
    __metaclass__ = ABCMeta

    # Class variables initialization
    branch = None
    project_id = None
    organization_id = None
    gcp_service_account = None
    user_can_grant_roles = True
    config = Config()

    @abstractmethod
    def __init__(self):
        """Initialize."""
        pass

    def run_setup(self):
        """Run the setup steps"""
        print_banner('Forseti %s Setup' % get_forseti_version())

        # Preflight checks
        self.preflight_checks()

        # Deployment
        bucket_name = self.generate_bucket_name(self.project_id,
                                                self.config.timestamp)
        conf_file_path = self.generate_forseti_conf()
        deployment_tpl_path = self.generate_deployment_templates()

        deploy_success, deployment_name = self.deploy(deployment_tpl_path,
                                                      conf_file_path,
                                                      bucket_name)

        # After deployment
        self.post_install_instructions(deploy_success,
                                       deployment_name,
                                       deployment_tpl_path,
                                       conf_file_path,
                                       bucket_name)

    def preflight_checks(self):
        """Pre-flight checks"""
        self.check_run_properties()
        self.branch = infer_version(self.config.advanced_mode)
        self.project_id, authed_user, is_devshell = get_gcloud_info()
        verify_gcloud_information(self.project_id,
                                  authed_user,
                                  self.config.force_no_cloudshell,
                                  is_devshell)
        self.organization_id = lookup_organization(self.project_id)
        check_billing_enabled(self.project_id, self.organization_id)
        self.format_gcp_service_acct_id()
        self.gcp_service_account = create_reuse_service_acct(
            'gcp_service_account',
            self.gcp_service_account,
            self.config.advanced_mode,
            self.config.dry_run)

    def deploy(self, deploy_tpl_path, conf_file_path, bucket_name):
        """Deploy Forseti using the deployment template

        Args:
            deploy_tpl_path (str): Deployment template path
            conf_file_path (str): Configuration file path
            bucket_name (str): Name of the GCS bucket

        Returns:
            bool: Whether or not the deployment was successful
            str: Deployment name
        """
        deployment_name, return_code = create_deployment(
            self.project_id,
            self.organization_id,
            deploy_tpl_path,
            self.config.template_type,
            self.config.datetimestamp,
            self.config.dry_run)
        if not return_code:
            # If deployed successfully, copy configuration file, deployment
            # template file and rule files to the GCS bucket
            conf_output_path = FORSETI_CONF_PATH.format(
                bucket_name=bucket_name,
                template_type=self.config.template_type)
            copy_file_to_destination(
                conf_file_path, conf_output_path,
                is_directory=False, dry_run=self.config.dry_run)

            dpl_tpl_output_path = DEPLOYMENT_TEMPLATE_OUTPUT_PATH.format(
                bucket_name)
            copy_file_to_destination(
                deploy_tpl_path, dpl_tpl_output_path,
                is_directory=False, dry_run=self.config.dry_run)

        return not return_code, deployment_name

    def check_run_properties(self):
        """Check script run properties."""
        print('Dry run? %s' % self.config.dry_run)
        print('Advanced mode? %s' % self.config.advanced_mode)

    def format_gcp_service_acct_id(self):
        """Format the service account ids."""
        self.gcp_service_account = format_service_acct_id('gcp',
                                                          'reader',
                                                          self.config.timestamp,
                                                          self.project_id)

    @staticmethod
    def generate_bucket_name(project_id, timestamp):
        """Generate GCS bucket name.

        Args:
            project_id (str): Project Id
            timestamp (str): Timestamp

        Returns:
            str: Name of the GCS bucket
        """
        return DEFAULT_BUCKET_FMT.format(project_id, timestamp)

    @abstractmethod
    def get_deployment_values(self):
        """Get deployment values

        Returns:
            dict: A dictionary of values needed to generate
                the forseti deployment template
        """
        return {}

    @abstractmethod
    def get_configuration_values(self):
        """Get configuration values

        Returns:
            dict: A dictionary of values needed to generate
                the forseti configuration file
        """
        return {}

    def generate_deployment_templates(self):
        """Generate deployment templates.

        Returns:
            str: Deployment template path
        """
        print('Generate Deployment Manager templates...')

        deploy_values = self.get_deployment_values()

        deploy_tpl_path = generate_deployment_templates(
            self.config.template_type,
            deploy_values,
            self.config.datetimestamp)

        print('\nCreated a deployment template:\n    %s\n' %
              deploy_tpl_path)
        return deploy_tpl_path

    def generate_forseti_conf(self):
        """Generate Forseti conf file.

        Returns:
            str: Forseti configuration file path
        """
        # Create a forseti_conf_$TIMESTAMP.yaml config file with
        # values filled in.
        # forseti_conf_server.yaml in file
        print('\nGenerate forseti_conf_{}_{}.yaml...'
              .format(self.config.template_type, self.config.datetimestamp))

        conf_values = self.get_configuration_values()

        forseti_conf_path = generate_forseti_conf(self.config.template_type,
                                                  conf_values,
                                                  self.config.datetimestamp)

        print('\nCreated forseti_conf_{}_{}.yaml config file:\n    {}\n'.
              format(self.config.template_type,
                     self.config.datetimestamp,
                     forseti_conf_path))
        return forseti_conf_path

    def post_install_instructions(self, deploy_success, deployment_name,
                                  deploy_tpl_path, forseti_conf_path,
                                  bucket_name):
        """Show post-install instructions

        Print link for deployment manager dashboard
        Print link to go to G Suite service account and enable DWD

        Args:
            deploy_success (bool): Whether deployment was successful
            deployment_name (str): Name of the deployment
            deploy_tpl_path (str): Deployment template path
            forseti_conf_path (str): Forseti configuration file path
            bucket_name (str): Name of the GCS bucket
        """
        print_banner('Post-setup instructions')

        if self.config.dry_run:
            print('This was a dry run, so a deployment was not attempted. '
                  'You can still create the deployment manually.\n')
        elif deploy_success:
            print(MESSAGE_FORSETI_BRANCH_DEPLOYED.format(self.branch))
        else:
            print(MESSAGE_DEPLOYMENT_HAD_ISSUES)

        deploy_tpl_gcs_path = DEPLOYMENT_TEMPLATE_OUTPUT_PATH.format(
            bucket_name)

        print(MESSAGE_DEPLOYMENT_TEMPLATE_LOCATION.format(
            deploy_tpl_path, deploy_tpl_gcs_path))

        if self.config.dry_run:
            print(MESSAGE_FORSETI_CONFIGURATION_GENERATED_DRY_RUN.format(
                forseti_conf_path, bucket_name))
        else:
            print(MESSAGE_VIEW_DEPLOYMENT_DETAILS.format(
                deployment_name,
                self.project_id,
                self.organization_id))

            print(MESSAGE_FORSETI_CONFIGURATION_GENERATED.format(
                template_type=self.config.template_type,
                datetimestamp=self.config.datetimestamp,
                bucket_name=bucket_name))