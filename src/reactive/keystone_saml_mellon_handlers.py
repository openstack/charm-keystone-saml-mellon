#
# Copyright 2017 Canonical Ltd
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

import charms_openstack.bus
charms_openstack.bus.discover()


import charms_openstack.charm as charm
import charms.reactive as reactive

charm.use_defaults(
    'charm.installed',
    'update-status',
    'upgrade-charm')


@reactive.when_not('keystone-fid-service-provider.connected')
def keystone_departed():
    """
    Service restart should be handled on the keystone side
    in this case.
    """
    with charm.provide_charm_instance() as charm_instance:
        charm_instance.remove_config()


@reactive.when('keystone-fid-service-provider.connected')
def publish_sp_fid(fid_sp):
    with charm.provide_charm_instance() as charm_instance:
        fid_sp.publish(charm_instance.options.protocol_name,
                       charm_instance.options.remote_id_attribute)


@reactive.when('keystone-fid-service-provider.available')
def render_config(fid_sp):
    with charm.provide_charm_instance() as charm_instance:
        if charm_instance.configuration_complete():
            charm_instance.render_config(fid_sp)
            # Trigger keystone restart. The relation is container-scoped
            # so a per-unit db of a remote unit will only contain a nonce
            # of a single subordinate
            if reactive.any_file_changed(charm_instance.restart_map.keys()):
                fid_sp.request_restart()


@reactive.when('websso-fid-service-provider.connected')
def configure_websso(websso_fid_sp):
    with charm.provide_charm_instance() as charm_instance:
        if charm_instance.configuration_complete():
            # publish config options for all remote units of a given rel
            options = charm_instance.options
            websso_fid_sp.publish(options.protocol_name,
                                  options.idp_name,
                                  options.user_facing_name)


@reactive.when_not('always.run')
def assess_status():
    with charm.provide_charm_instance() as charm_instance:
        charm_instance.assess_status()
