# Copyright (C) 2015 eNovance SAS <lei.guo@tcl.com>
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
from neutron.api.rpc.agentnotifiers import metering_rpc_agent_api
from neutron.services.metering import metering_plugin

class MeteringAgentRpcCallback(metering_plugin.metering_plugin):
    
    def __init__(self):
        self.meter_rpc = metering_rpc_agent_api.MeteringAgentNotifyAPI()