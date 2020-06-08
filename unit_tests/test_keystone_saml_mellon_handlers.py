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

from unittest import mock

import charm.openstack.keystone_saml_mellon as keystone_saml_mellon
import reactive.keystone_saml_mellon_handlers as handlers

import charms_openstack.test_utils as test_utils


class TestRegisteredHooks(test_utils.TestRegisteredHooks):

    def test_hooks(self):
        defaults = [
            'charm.installed',
            'update-status']
        hook_set = {
            'hook': {
                'default_upgrade_charm': ('upgrade-charm',),
            },
            'when': {
                'publish_sp_fid': (
                    'keystone-fid-service-provider.connected',),
                'render_config': (
                    'keystone-fid-service-provider.available',),
                'configure_websso': (
                    'websso-fid-service-provider.connected',),
            },
            'when_not': {
                'keystone_departed': (
                    'keystone-fid-service-provider.connected',),
                'assess_status': ('always.run',),
            },
        }
        # test that the hooks were registered via the
        # reactive.keystone_saml_mellon_handlers
        self.registered_hooks_test_helper(handlers, hook_set, defaults)


class TestKeystoneSAMLMellonHandlers(test_utils.PatchHelper):

    def setUp(self):
        super().setUp()
        self.patch_release(
            keystone_saml_mellon.KeystoneSAMLMellonCharm.release)
        self.keystone_saml_mellon_charm = mock.MagicMock()
        self.patch_object(handlers.charm, 'provide_charm_instance',
                          new=mock.MagicMock())
        self.provide_charm_instance().__enter__.return_value = (
            self.keystone_saml_mellon_charm)
        self.provide_charm_instance().__exit__.return_value = None

        self.patch_object(handlers.reactive, 'any_file_changed',
                          new=mock.MagicMock())

        self.endpoint = mock.MagicMock()

        self.protocol_name = "mapped"
        self.remote_id_attribute = "https://samltest.id"
        self.idp_name = "samltest"
        self.user_facing_name = "samltest.id"
        self.keystone_saml_mellon_charm.options.protocol_name = (
            self.protocol_name)
        self.keystone_saml_mellon_charm.options.remote_id_attribute = (
            self.remote_id_attribute)
        self.keystone_saml_mellon_charm.options.idp_name = self.idp_name
        self.keystone_saml_mellon_charm.options.user_facing_name = (
            self.user_facing_name)

        self.all_joined_units = []
        for i in range(0, 2):
            unit = mock.MagicMock()
            unit.name = "keystone-{}".format(i)
            unit.recieved = {"hostname": unit.name,
                             "port": "5000",
                             "tls-enabled": True}
            self.all_joined_units.append(unit)

    def test_keystone_departed(self):
        handlers.keystone_departed()
        self.keystone_saml_mellon_charm.remove_config.assert_called_once_with()

    def test_publish_sp_fid(self):
        handlers.publish_sp_fid(self.endpoint)
        self.endpoint.publish.assert_called_once_with(
            self.protocol_name, self.remote_id_attribute)

    def test_render_config(self):
        # No restart
        self.any_file_changed.return_value = False
        (self.keystone_saml_mellon_charm
            .configuration_complete.return_value) = True

        handlers.render_config(self.endpoint)
        self.keystone_saml_mellon_charm.render_config.assert_called_once_with(
            self.endpoint)
        self.endpoint.request_restart.assert_not_called()

        # Restart
        self.any_file_changed.return_value = True
        handlers.render_config(self.endpoint)
        self.endpoint.request_restart.assert_called_once_with()

    def test_configure_websso(self):
        handlers.configure_websso(self.endpoint)
        self.endpoint.publish.assert_called_once_with(
            self.protocol_name, self.idp_name, self.user_facing_name)

    def test_assess_status(self):
        handlers.assess_status()
        self.keystone_saml_mellon_charm.assess_status.assert_called_once_with()
