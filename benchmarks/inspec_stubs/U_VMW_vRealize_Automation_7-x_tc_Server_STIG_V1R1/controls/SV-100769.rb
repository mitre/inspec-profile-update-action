control 'SV-100769' do
  title 'tc Server VCAC must be configured to use the https scheme.'
  desc "Remote access to the web server is any access that communicates through an external, non-organization-controlled network. Remote access can be used to access hosted applications or to perform management functions.

tc Server connections are managed by the Connector object class. By configuring external Connector objects to use the HTTPS scheme, vRA's information in flight will be protected."
  desc 'check', 'Navigate to and open /etc/vcac/server.xml.

Navigate to the <Connector> node.

If the value of "scheme" is not set to "https" or is missing, this is a finding.'
  desc 'fix', %q(Navigate to and open /etc/vcac/server.xml.

Navigate to the <Connector> node.

Configure the <Connector> node with the value 'scheme="https"'.)
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x tcServer'
  tag check_id: 'C-89811r1_chk'
  tag severity: 'medium'
  tag gid: 'V-90119'
  tag rid: 'SV-100769r1_rule'
  tag stig_id: 'VRAU-TC-000720'
  tag gtitle: 'SRG-APP-000315-WSR-000004'
  tag fix_id: 'F-96861r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
