#!/usr/local/sbin/charm-env python3
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

import os
import sys
import charmhelpers.core.hookenv as hookenv


SP_METADATA_FILE = "/etc/apache2/mellon/sp-meta.keystone-saml-mellon.xml"


def get_sp_metadata(*args):
    if not os.path.exists(SP_METADATA_FILE):
        return hookenv.action_fail(
            "The SP metadata file {} does not exist"
            .format(SP_METADATA_FILE))
    sp_metadata = ""
    # By stripping double new lines and tabs we get human readable xml
    # Otherwise, show-action-status is a garbled mess
    with open(SP_METADATA_FILE, 'r') as f:
        for line in f.readlines():
            line = line.replace("\t", "  ")
            if line.strip(" ") == "\n":
                continue
            sp_metadata += line
    return hookenv.action_set({"output": sp_metadata})


ACTIONS = {
    'get-sp-metadata': get_sp_metadata,
}


def main(args):
    action_name = os.path.basename(args[0])
    try:
        action = ACTIONS[action_name]
    except KeyError:
        return 'Action {} undefined'.format(action_name)
    else:
        try:
            action(args)
        except Exception as e:
            hookenv.action_fail(str(e))


if __name__ == '__main__':
    sys.exit(main(sys.argv))
