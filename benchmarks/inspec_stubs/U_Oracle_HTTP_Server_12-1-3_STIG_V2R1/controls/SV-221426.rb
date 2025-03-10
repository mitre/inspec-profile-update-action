control 'SV-221426' do
  title 'The listen-address element defined within the config.xml of the OHS Standalone domain that supports OHS must be configured for secure communication.'
  desc 'Oracle Node Manager is the utility that is used to perform common operational tasks for OHS.

When starting an OHS instance, the WebLogic Scripting Tool reads the parameters within the config.xml file to setup the communication to the Node Manager.  If the IP address to be used for communication is not specified, the WebLogic Scripting tool will not be able to setup a secure connection to Node Manager.'
  desc 'check', '1. Open $DOMAIN_HOME/config/config.xml with an editor.

2. Search for the "<listen-address>" element within the "<node-manager>" element.

3. If the element does not exist or is not set to the CN of the Node Manager certificate, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/config.xml with an editor.

2. Search for the "<listen-address>" element within the "<node-manager>" element.

3. Set the "<listen-address>" element to the CN of the Node Manager certificate, add the element if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23141r414961_chk'
  tag severity: 'medium'
  tag gid: 'V-221426'
  tag rid: 'SV-221426r414963_rule'
  tag stig_id: 'OH12-1X-000187'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-23130r414962_fix'
  tag 'documentable'
  tag legacy: ['SV-79103', 'V-64613']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
