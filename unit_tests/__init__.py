# Copyright 2019 Canonical Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys

sys.path.append('src')
sys.path.append('src/lib')
sys.path.append('src/actions')

# Mock out charmhelpers so that we can test without it.
# NOTE: The bellow mocks are to avoid side effects at import time.
# Any module that requires testing must be re-mocked before usage
# in a unit test.
import charms_openstack.test_mocks  # noqa
charms_openstack.test_mocks.mock_charmhelpers()

from unittest import mock
import charms
keystoneauth1 = mock.MagicMock()
sys.modules['keystoneauth1'] = keystoneauth1
charms.leadership = mock.MagicMock()
sys.modules['charms.leadership'] = charms.leadership
