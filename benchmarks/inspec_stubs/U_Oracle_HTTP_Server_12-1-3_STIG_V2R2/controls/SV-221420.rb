control 'SV-221420' do
  title 'The AuthenticationEnabled property of the Node Manager configured to support OHS must be configured to enforce authentication.'
  desc 'Oracle Node Manager is the utility that is used to perform common operational tasks for OHS.

To accept connections from the WebLogic Scripting Tool, the Node Manager can be setup to authenticate the connections or not.  If connections are not authenticated, a hacker could connect to the Node Manager and initiate commands to OHS to gain further access, cause a DoS, or view protected information.  To protect against unauthenticated connections, the "AuthenticationEnabled" directive must be set to "true".'
  desc 'check', '1. Open $DOMAIN_HOME/nodemanager/nodemanager.properties with an editor.

2. Search for the "AuthenticationEnabled" property.

3. If the property does not exist or is not set "True", this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/nodemanager/nodemanager.properties with an editor.

2. Search for the "AuthenticationEnabled" property.

3. Set the "AuthenticationEnabled" property "True", add the property if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23135r414943_chk'
  tag severity: 'medium'
  tag gid: 'V-221420'
  tag rid: 'SV-221420r879887_rule'
  tag stig_id: 'OH12-1X-000181'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-23124r414944_fix'
  tag 'documentable'
  tag legacy: ['SV-79091', 'V-64601']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
