control 'SV-79087' do
  title 'The SecureListener property of the Node Manager configured to support OHS must be enabled for secure communication.'
  desc 'Oracle Node Manager is the utility that is used to perform common operational tasks for OHS.

To protect the information being sent between WebLogic Scripting Tool and Node Manager, the Node Manager listening address must be secured.'
  desc 'check', '1. Open $DOMAIN_HOME/nodemanager/nodemanager.properties with an editor.

2. Search for the "SecureListener" property.

3. If the property is not set to "True", this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/nodemanager/nodemanager.properties with an editor.

2. Search for the "SecureListener" property.

3. Set the "SecureListener" property to "True".'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server (OHS) 12.1.x'
  tag check_id: 'C-65339r1_chk'
  tag severity: 'medium'
  tag gid: 'V-64597'
  tag rid: 'SV-79087r1_rule'
  tag stig_id: 'OH12-1X-000179'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-70527r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
