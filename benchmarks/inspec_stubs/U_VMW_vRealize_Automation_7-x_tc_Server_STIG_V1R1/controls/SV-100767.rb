control 'SV-100767' do
  title 'tc Server HORIZON must be configured to use the https scheme.'
  desc "Remote access to the web server is any access that communicates through an external, non-organization-controlled network. Remote access can be used to access hosted applications or to perform management functions.

tc Server connections are managed by the Connector object class. By configuring external Connector objects to use the HTTPS scheme, vRA's information in flight will be protected."
  desc 'check', 'Navigate to and open /opt/vmware/horizon/workspace/conf/server.xml.

Navigate to each of the <Connector> nodes.

If the value of "scheme" is not set to "https" or is missing, this is a finding.'
  desc 'fix', %q(Navigate to and open /opt/vmware/horizon/workspace/conf/server.xml.

Navigate to each of the <Connector> nodes.

Configure each <Connector> node with the value 'scheme="https"'.)
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x tcServer'
  tag check_id: 'C-89809r1_chk'
  tag severity: 'medium'
  tag gid: 'V-90117'
  tag rid: 'SV-100767r1_rule'
  tag stig_id: 'VRAU-TC-000715'
  tag gtitle: 'SRG-APP-000315-WSR-000004'
  tag fix_id: 'F-96859r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
