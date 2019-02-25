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

import uuid

# import to trigger openstack charm metaclass init
import charm.openstack.keystone_saml_mellon # noqa

import charms_openstack.charm as charm
import charms.reactive as reactive
import charms.reactive.flags as flags

import charmhelpers.core.unitdata as unitdata

from charms.reactive.relations import (
    endpoint_from_flag,
)

charm.use_defaults(
    'charm.installed',
    'update-status')

# if config has been changed we need to re-evaluate flags
# config.changed is set and cleared (atexit) in layer-basic
flags.register_trigger(when='config.changed',
                       clear_flag='config.rendered')
flags.register_trigger(when='upgraded', clear_flag='config.rendered')
flags.register_trigger(when='config.changed',
                       clear_flag='config.complete')
flags.register_trigger(
    when='endpoint.keystone-fid-service-provider.changed',
    clear_flag='keystone-data.complete'
)


@reactive.hook('upgrade-charm')
def default_upgrade_charm():
    """Default handler for the 'upgrade-charm' hook.
    This calls the charm.singleton.upgrade_charm() function as a default.
    """
    reactive.set_state('upgraded')


# clear the upgraded state once config.rendered is set again
flags.register_trigger(when='config.rendered', clear_flag='upgraded')


@reactive.when_not('endpoint.keystone-fid-service-provider.joined')
def keystone_departed():
    """
    Service restart should be handled on the keystone side
    in this case.
    """
    with charm.provide_charm_instance() as charm_instance:
        charm_instance.remove_config()


@reactive.when('endpoint.keystone-fid-service-provider.joined')
@reactive.when_not('config.complete')
def config_changed():
    with charm.provide_charm_instance() as charm_instance:
        if charm_instance.configuration_complete():
            flags.set_flag('config.complete')


@reactive.when('endpoint.keystone-fid-service-provider.joined')
@reactive.when_not('keystone-data.complete')
def keystone_data_changed(fid_sp):
    primary_data = fid_sp.all_joined_units[0].received
    if primary_data:
        hostname = primary_data.get('hostname')
        port = primary_data.get('port')
        tls_enabled = primary_data.get('tls-enabled')
        # a basic check on the fact that keystone provided us with
        # hostname and port information
        if hostname and port:
            # save hostname and port data in local storage for future
            # use - in case config is incomplete but a relation is
            # we need to store this across charm hook invocations
            unitdb = unitdata.kv()
            unitdb.set('hostname', hostname)
            unitdb.set('port', port)
            unitdb.set('tls-enabled', tls_enabled)
            flags.set_flag('keystone-data.complete')


@reactive.when('endpoint.keystone-fid-service-provider.joined')
@reactive.when('config.complete')
@reactive.when('keystone-data.complete')
@reactive.when_not('config.rendered')
def render_config():
    # don't always have a relation context - obtain from the flag
    fid_sp = endpoint_from_flag(
        'endpoint.keystone-fid-service-provider.joined')
    with charm.provide_charm_instance() as charm_instance:
        charm_instance.render_config()
        flags.set_flag('config.rendered')
        # Trigger keystone restart. The relation is container-scoped
        # so a per-unit db of a remote unit will only contain a nonce
        # of a single subordinate
        restart_nonce = str(uuid.uuid4())
        fid_sp.publish(restart_nonce,
                       charm_instance.options.protocol_name,
                       charm_instance.options.remote_id_attribute)


@reactive.when('endpoint.websso-fid-service-provider.joined')
@reactive.when('config.complete')
@reactive.when('keystone-data.complete')
@reactive.when('config.rendered')
def configure_websso():
    # don't always have a relation context - obtain from the flag
    websso_fid_sp = endpoint_from_flag(
        'endpoint.websso-fid-service-provider.joined')
    with charm.provide_charm_instance() as charm_instance:
        # publish config options for all remote units of a given rel
        options = charm_instance.options
        websso_fid_sp.publish(options.protocol_name,
                              options.idp_name,
                              options.user_facing_name)


@reactive.when_not('always.run')
def assess_status():
    with charm.provide_charm_instance() as charm_instance:
        charm_instance.assess_status()
