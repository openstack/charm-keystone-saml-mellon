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

from __future__ import absolute_import
from __future__ import print_function

import mock

import charms_openstack.test_utils as test_utils

import actions


class TestKeystoneSAMLMellonActions(test_utils.PatchHelper):

    def setUp(self):
        super().setUp()
        self.patch_object(actions.hookenv, 'action_set')
        self.patch_object(actions.hookenv, 'action_fail')
        self.patch_object(actions.hookenv, 'service_name')
        self.patch_object(actions, "os")

        self.patch(
            "builtins.open", new_callable=mock.mock_open(), name="open")
        self.file = mock.MagicMock()
        self.fileobj = mock.MagicMock()
        self.fileobj.__enter__.return_value = self.file
        self.open.return_value = self.fileobj

    def test_get_sp_metadata(self):
        service_name = 'keystone-foobar-mellon'
        self.service_name.return_value = service_name

        # Valid XML
        self.sp_metadata_xml = (
            "<?xml version='1.0' encoding='UTF-8'?>"
            "<ds:KeyInfo xmlns:ds='http://www.w3.org/2000/09/xmldsig#'>"
            "<ds:X509Data> <ds:X509Certificate> </ds:X509Certificate>"
            "</ds:X509Data> </ds:KeyInfo>")
        self.file.readlines.return_value = self.sp_metadata_xml
        self.metadata_file = ("/etc/apache2/mellon/"
                              "sp-meta.{}.xml".format(
                                  service_name))

        # File Does not exist
        self.os.path.exists.return_value = False
        actions.get_sp_metadata()
        self.action_fail.assert_called_once_with(
            "The SP metadata file {} does not exist"
            .format(self.metadata_file))

        # File exists
        self.os.path.exists.return_value = True
        actions.get_sp_metadata()
        self.action_set.assert_called_once_with(
            {"output": self.sp_metadata_xml})
