control 'SV-221540' do
  title 'OHS must have the SSLFIPS directive enabled to maintain the confidentiality and integrity of information during reception.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during reception, including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

Protecting the confidentiality and integrity of received information requires that application servers take measures to employ approved cryptography in order to protect the information during transmission over the network. This is usually achieved through the use of Transport Layer Security (TLS), SSL VPN, or IPsec tunnel. 

The web server must utilize approved encryption when receiving transmitted data.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/ssl.conf with an editor.

2. Search for the "SSLFIPS" directive at the OHS server configuration scope.

3. If the directive is omitted or is not set to "On", this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/ssl.conf with an editor.

2. Search for the "SSLFIPS" directive at the OHS server configuration scope.

3. Set the "SSLFIPS" directive to "On", add the directive if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23255r415299_chk'
  tag severity: 'medium'
  tag gid: 'V-221540'
  tag rid: 'SV-221540r415301_rule'
  tag stig_id: 'OH12-1X-000332'
  tag gtitle: 'SRG-APP-000442-WSR-000182'
  tag fix_id: 'F-23244r415300_fix'
  tag 'documentable'
  tag legacy: ['SV-79071', 'V-64581']
  tag cci: ['CCI-002422']
  tag nist: ['SC-8 (2)']
end
