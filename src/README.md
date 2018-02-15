# Overview

This subordinate charm provides a way to integrate a SAML-based identity
provider with Keystone using Mellon Apache web server authentication
module (mod_auth_mellon) and lasso as its dependency. Mellon acts as a
Service Provider in this case and provides SAML token attributes as WSGI
environment variables to Keystone which does not itself participate in
SAML exchanges - it merely interprets results of such exchanges
and maps assertion-derived attributes to entities (such as groups,
roles, projects and domains) in a local Keystone SQL database.

In general, any identity provider that conforms to SAML 2.0 will be
possible to integrate using this charm.

The following documentation is useful to better understand the charm
implementation:

* https://github.com/UNINETT/mod_auth_mellon/blob/master/doc/user_guide/mellon_user_guide.adoc
* https://github.com/UNINETT/mod_auth_mellon/blob/master/doc/user_guide/images/saml-web-sso.svg
* http://lasso.entrouvert.org/
* https://www.oasis-open.org/standards#samlv2.0

# Usage

Use this charm with the Keystone charm, running with preferred-api-version=3:

    juju deploy keystone
    juju config keystone preferred-api-version=3 # other settings
    juju deploy openstack-dashboard # settings
    juju deploy keystone-saml-mellon
    juju add-relation keystone keystone-saml-mellon
    juju add-relation keystone openstack-dashboard


In a bundle:

```
    applications:
    # ...
      keystone-saml-mellon:
        charm: cs:~dmitriis/keystone-saml-mellon
        num_units: 0
        options:
          idp-name: 'myidp'
          protocol-name: 'saml2'
          user-facing-name: "myidp via saml2'
        resources:
          idp-metadata: "./FederationMetadata.xml"
          sp-signing-keyinfo: "./sp-keyinfo.xml"
          sp-private-key: "./mellon.pem"
      relations:
      # ...
      - [ keystone, keystone-saml-mellon ]
      - [ openstack-dashboard, keystone-saml-mellon ]
      - [ "openstack-dashboard:websso-trusted-dashboard", "keystone:websso-trusted-dashboard" ]
```

# Prerequisites

In order to use this charm, there are several prerequisites that need to be
taken into account which require certain infrastructure to be set up out of
band, namely:

* PKI;
* DNS;
* NTP;
* idP.

On the Keystone charm side, this means that ssl_ca, ssl_cert, ssl_key,
use-https and os-public-hostname must be set.

Several key pairs can be used in a generic SAML exchange along with
certificates containing public keys. Besides the pairs used for message-level
signing and encryption there are also TLS certificates used for transport
layer encryption when a browser connects to a protected URL on the SP side or
when it gets redirected to an idP endpoint for authentication. In summary:

* Service Provider (Keystone) TLS termination certificates, keys and CA;
* Service Provider signing and encryption private keys and associated
  public keys (SAML-level);
* Identity Provider TLS termination certificates, keys and CA;
* Identity Provider signing and encryption private keys and associated public
  keys (SAML-level).

For a successful authentication to happen the following needs to hold:

* A user agent (browser) needs to
  * trust an issuer (CA) of TLS certificates of an SP used for HTTPS;
  * trust an issuer (CA) TLS certificates of an idP used for HTTPS;
  * be able to resolve domain names present in subject or subjAltName fields.
* An SP needs to:
  * be able to verify signed SAML messages sent by an idP via
    public keys contained in certificates provided in the idP's metadata XML
    and, if SAML-level encryption is enabled, decrypt those messages;
* An idP needs to:
  * be able to verify signed SAML messages sent by an SP via
    public keys contained in certificates provided in the SP's metadata XML
    and, if SAML-level encryption is enabled, decrypt those messages.

Note that this does not mean that any actual checks are performed for
certificates related to SAML - only key material is used and there does
NOT have to be any PKI actually in-place, not even expiration times are
checked as per Mellon documentation. In that sense trust is very explicitly
defined by out of band mutual synchronization of SP and idP metadata files.
See SAML V2.0 Metadata Interoperability Profile (2.6.1) key processing
section for a normative reference.

However, this does not mean that no PKI will be in place - TLS certificates
used for HTTPS connectivity have to be verifiable by the entities that use
them. With Redirect or POST binding this is mainly about user agent being
able to validate SP or idP certificates - there is no direct communication
between the two outside the metadata synchronization step which is performed
by an operator out of band.

Additionally, for successful certificate verification clocks of all parties
need to be properly synchronized which is why it is important for NTP agents
to be able to reach proper NTP servers on SP and idP.

# Post-deployment Configuration

There are several post-deployment steps that have to be performed in order to
start using federated identity functionality in Keystone. They depend on the
chosen config values and also on an IDP configuration as it may put different
NameID values and attributes into SAML tokens. Token attributes are parsed by
mod_auth_mellon and are placed into WSGI environment which are used by
Keystone and they have the following format: "MELLON_<attribute_name>"
(one attribute can have multiple values in SAML). Both NameID and attribute
values can be used in mappings to map SAML token content to existing and, in
case of projects, potentially non-existing entities in Keystone database.

In order to take the above into account several objects need to be created:

* a domain used for federated users;
* (optional) a project to be used by federated users;
* one or more groups to place federated users into;
* role assignments for the groups above;
* an identity provider object;
* a mapping of NameID and SAML token attributes to Keystone entities;
* a federation protocol object.

```
    cat > rules.json <<EOF
    [{
            "local": [
                {
                    "user": {
                        "name": "{0}"
                    },
                    "group": {
                        "domain": {
                            "name": "federated_domain"
                        },
                        "name": "federated_users"
                    },
                    "projects": [
                    {
                        "name": "{0}",
                        "roles": [
                                     {
                                         "name": "Member"
                                     }
                                 ]
                    }
                    ]
               }
            ],
            "remote": [
                {
                    "type": "MELLON_NAME_ID"
                },
                {
                    "type": "MELLON_groups",
                    "any_one_of": ["openstack-users"]
                }
            ]
    }]
    EOF
    openstack domain create federated_domain
    openstack project create federated_project --domain federated_domain
    openstack group create federated_users --domain federated_domain
    # created group id: 0427a780b34441488f064526a9890edd
    openstack role add --group 0427a780b34441488f064526a9890edd --domain federated_domain Member
    openstack identity provider create --remote-id https://adfs.intranet.test/adfs/services/trust myidp
    openstack mapping create --rules rules.json myidp_mapping
    openstack federation protocol create mapped --mapping myidp_mapping --identity-provider myidp
    # list related projects
    openstack federation project list
```

# Bugs

Please report bugs on [Launchpad](https://bugs.launchpad.net/charm-keystone-saml-mellon/+filebug).

For general questions please refer to the OpenStack [Charm Guide](http://docs.openstack.org/developer/charm-guide/).
