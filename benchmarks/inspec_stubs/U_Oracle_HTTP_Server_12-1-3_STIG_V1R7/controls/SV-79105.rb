control 'SV-79105' do
  title 'The listen-port element defined within the config.xml of the OHS Standalone Domain must be configured for secure communication.'
  desc 'Oracle Node Manager is the utility that is used to perform common operational tasks for OHS.

When starting an OHS instance, the WebLogic Scripting Tool reads the parameters within the config.xml file to setup the communication to the Node Manager.  If the port to be used for communication is not specified, the WebLogic Scripting tool will not be able to setup a secure connection to Node Manager.'
  desc 'check', '1. Open $DOMAIN_HOME/config/config.xml with an editor.

2. Search for the "<listen-port>" element within the "<node-manager>" element.

3. If the element does not exist or is not set to the same value as the "ListenPort" property found in $DOMAIN_HOME/nodemanager/nodemanager.properties, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/config.xml with an editor.

2. Search for the "<listen-port>" element within the "<node-manager>" element.

3. Set the "<listen-port>" element to same value as the "ListenPort" property found in $DOMAIN_HOME/nodemanager/nodemanager.properties, add the element if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server (OHS) 12.1.x'
  tag check_id: 'C-65357r1_chk'
  tag severity: 'medium'
  tag gid: 'V-64615'
  tag rid: 'SV-79105r1_rule'
  tag stig_id: 'OH12-1X-000188'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-70545r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
