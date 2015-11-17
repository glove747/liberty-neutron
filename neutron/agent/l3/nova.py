# Copyright (c) 2014 OpenStack Foundation.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from keystoneclient import auth as ks_auth
from keystoneclient.auth.identity import v2 as v2_auth
from keystoneclient import session as ks_session
from novaclient import client as nova_client
from novaclient import exceptions as nova_exceptions
from oslo_config import cfg
from oslo_serialization import jsonutils
from oslo_log import log as logging

from neutron.i18n import _LE, _LW


LOG = logging.getLogger(__name__)

NOVA_API_VERSION = "2"


class DefaultAuthPlugin(v2_auth.Password):

    def __init__(self, **kwargs):
        self._endpoint_override = kwargs.pop('endpoint_override', None)
        super(DefaultAuthPlugin, self).__init__(**kwargs)

    def get_endpoint(self, session, **kwargs):
        if self._endpoint_override:
            return self._endpoint_override

        return super(DefaultAuthPlugin, self).get_endpoint(session, **kwargs)


class NovaClient(object):

    def __init__(self):
        auth = ks_auth.load_from_conf_options(cfg.CONF, 'nova')
        endpoint_override = None

        if not auth:
            LOG.warning(_LW('Authenticating to nova using nova_admin_* options'
                            ' is deprecated. This should be done using'
                            ' an auth plugin, like password'))

            if cfg.CONF.nova_admin_tenant_id:
                endpoint_override = "%s/%s" % (cfg.CONF.nova_url,
                                               cfg.CONF.nova_admin_tenant_id)

            auth = DefaultAuthPlugin(
                auth_url=cfg.CONF.nova_admin_auth_url,
                username=cfg.CONF.nova_admin_username,
                password=cfg.CONF.nova_admin_password,
                tenant_id=cfg.CONF.nova_admin_tenant_id,
                tenant_name=cfg.CONF.nova_admin_tenant_name,
                endpoint_override=endpoint_override)

        session = ks_session.Session.load_from_conf_options(cfg.CONF,
                                                            'nova',
                                                            auth=auth)

        self.nclient = nova_client.Client(
            NOVA_API_VERSION,
            session=session,
            region_name=cfg.CONF.nova.region_name)

    def get_instance(self, instance_id):
        LOG.debug("Getting instance: %s", instance_id)
        try:
            instance = self.nclient.servers.get(instance_id)
            return instance
        except nova_exceptions.NotFound, err:
            LOG.warning(_LW("Nova returned NotFound for instance: %s, "
                            "error: %s"), instance_id, err)
            raise err
        except Exception, err:
            LOG.exception(_LE("Failed to get nova instance: %s, error: %s"),
                          instance_id, err)
            raise err

    def get_metadata(self, instance_id, key=None, json=True):
        LOG.debug("Getting metadata, parameter instance_id: %s, key: %s",
                  instance_id, key)
        try:
            instance = self.get_instance(instance_id)
            metadata = instance.metadata
            if key:
                if key in metadata:
                    metadata = metadata[key]
                    if json:
                        metadata = jsonutils.loads(metadata)
                else:
                    metadata = {}
            LOG.debug("Metadata: %s", metadata)
            return metadata
        except Exception, err:
            LOG.exception(_LE("Failed to get metadata of instance: %s, "
                              "error: %s"), instance_id, err)
            raise err
