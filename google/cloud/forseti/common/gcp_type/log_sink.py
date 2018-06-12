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

"""A Stackdriver Log Sink

See: https://cloud.google.com/logging/docs/reference/v2/rest/v2/sinks
"""

from google.cloud.forseti.common.gcp_type import resource

class LogSink(resource.Resource):
    """Represents a Log Sink resource."""

    def __init__(self, **kwargs):
        """Log Sink resource.

        Args:
            **kwargs (dict): The keyworded variable args.
        """
        self.name = kwargs.get('name')
        self.destination = kwargs.get('destination')
        self.filter = kwargs.get('filter')
        self.writer_identity = kwargs.get('writer_identity')
        self.include_children = kwargs.get('include_children')
