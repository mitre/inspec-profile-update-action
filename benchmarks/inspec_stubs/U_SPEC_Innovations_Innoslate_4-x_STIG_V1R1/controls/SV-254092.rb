control 'SV-254092' do
  title 'Innoslate must generate comprehensive audit records.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one. 

Audit records can be generated from various components within the information system (e.g., module or policy filter).

1. Access Innoslate folder.
2. Navigate to Innoslate4\\apache-tomcat\\logs.
3. View the access logs.

'
  desc 'check', '1. Locate the logging.properties file in the following directory: Innoslate\\apache-tomcat\\conf.
2. Search "level", and check corresponding lines for the correct verbosity settings. If they are incorrect after a change, save, and service restart, this is a finding.

Below is an example of the contents of the default logging.properties file.

"# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

handlers = 1catalina.org.apache.juli.AsyncFileHandler, 2localhost.org.apache.juli.AsyncFileHandler, 3manager.org.apache.juli.AsyncFileHandler, 4host-manager.org.apache.juli.AsyncFileHandler, java.util.logging.ConsoleHandler

.handlers = 1catalina.org.apache.juli.AsyncFileHandler, java.util.logging.ConsoleHandler

############################################################
# Handler specific properties.
# Describes specific configuration info for Handlers.
############################################################

1catalina.org.apache.juli.AsyncFileHandler.level = FINE
1catalina.org.apache.juli.AsyncFileHandler.directory = ${catalina.base}/logs
1catalina.org.apache.juli.AsyncFileHandler.prefix = catalina.

2localhost.org.apache.juli.AsyncFileHandler.level = FINE
2localhost.org.apache.juli.AsyncFileHandler.directory = ${catalina.base}/logs
2localhost.org.apache.juli.AsyncFileHandler.prefix = localhost.

3manager.org.apache.juli.AsyncFileHandler.level = FINE
3manager.org.apache.juli.AsyncFileHandler.directory = ${catalina.base}/logs
3manager.org.apache.juli.AsyncFileHandler.prefix = manager.

4host-manager.org.apache.juli.AsyncFileHandler.level = FINE
4host-manager.org.apache.juli.AsyncFileHandler.directory = ${catalina.base}/logs
4host-manager.org.apache.juli.AsyncFileHandler.prefix = host-manager.

java.util.logging.ConsoleHandler.level = FINE
java.util.logging.ConsoleHandler.formatter = org.apache.juli.OneLineFormatter


############################################################
# Facility specific properties.
# Provides extra control for each logger.
############################################################

org.apache.catalina.core.ContainerBase.[Catalina].[localhost].level = INFO
org.apache.catalina.core.ContainerBase.[Catalina].[localhost].handlers = 2localhost.org.apache.juli.AsyncFileHandler

org.apache.catalina.core.ContainerBase.[Catalina].[localhost].[/manager].level = INFO
org.apache.catalina.core.ContainerBase.[Catalina].[localhost].[/manager].handlers = 3manager.org.apache.juli.AsyncFileHandler

org.apache.catalina.core.ContainerBase.[Catalina].[localhost].[/host-manager].level = INFO
org.apache.catalina.core.ContainerBase.[Catalina].[localhost].[/host-manager].handlers = 4host-manager.org.apache.juli.AsyncFileHandler

# For example, set the org.apache.catalina.util.LifecycleBase logger to log
# each component that extends LifecycleBase changing state:
#org.apache.catalina.util.LifecycleBase.level = FINE

# To see FINE messages in TldLocationsCache, uncomment the following line:
#org.apache.jasper.compiler.TldLocationsCache.level = FINE

# To see FINE messages for HTTP/2 handling, uncomment the following line:
#org.apache.coyote.http2.level = FINE

# To see FINE messages for WebSocket handling, uncomment the following line:
#org.apache.tomcat.websocket.level = FINE"'
  desc 'fix', '1. Locate the logging.properties file in the following directory: Innoslate4\\apache-tomcat\\conf.
2. Search "level" and modify corresponding lines to be set to FINE or VERBOSE as needed.'
  impact 0.5
  ref 'DPMS Target SPEC Innovations Innoslate 4.x'
  tag check_id: 'C-57577r845250_chk'
  tag severity: 'medium'
  tag gid: 'V-254092'
  tag rid: 'SV-254092r845252_rule'
  tag stig_id: 'SPEC-IN-000140'
  tag gtitle: 'SRG-APP-000091'
  tag fix_id: 'F-57528r845251_fix'
  tag satisfies: ['SRG-APP-000091', 'SRG-APP-000092', 'SRG-APP-000095', 'SRG-APP-000096', 'SRG-APP-000097', 'SRG-APP-000492', 'SRG-APP-000493', 'SRG-APP-000494', 'SRG-APP-000504', 'SRG-APP-000505', 'SRG-APP-000506', 'SRG-APP-000507', 'SRG-APP-000508', 'SRG-APP-000509', 'SRG-APP-000510']
  tag 'documentable'
  tag cci: ['CCI-000130', 'CCI-000131', 'CCI-000132', 'CCI-000172', 'CCI-001464']
  tag nist: ['AU-3 a', 'AU-3 b', 'AU-3 c', 'AU-12 c', 'AU-14 (1)']
end
