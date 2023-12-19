control 'SV-100837' do
  title 'tc Server HORIZON must use approved Transport Layer Security (TLS) versions to maintain the confidentiality and integrity of information during reception.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during reception, including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

Protecting the confidentiality and integrity of received information requires that application servers take measures to employ approved cryptography in order to protect the information during transmission over the network. This is usually achieved through the use of Transport Layer Security (TLS), SSL VPN, or IPsec tunnel. 

tc Server connections are managed by the Connector object class. The Connector object can be configured to use a range of transport encryption methods. Many older transport encryption methods have been proven to be weak. vRA should be configured to use the sslEnabledProtocols correctly to ensure that older, less secure forms of transport security are not used.'
  desc 'check', 'Navigate to and open /opt/vmware/horizon/workspace/conf/server.xml.

Navigate to each of the <Connector> nodes.

If the value of "sslEnabledProtocols" is not set to "TLSv1.2,TLSv1.1,TLSv1" or is missing, this is a finding.'
  desc 'fix', %q(Navigate to and open /opt/vmware/horizon/workspace/conf/server.xml.

Navigate to each of the <Connector> nodes.

Note: There are three <Connector> nodes.

Configure each <Connector> node with the setting 'sslEnabledProtocols="TLSv1.2,TLSv1.1,TLSv1"'.)
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x tcServer'
  tag check_id: 'C-89879r1_chk'
  tag severity: 'medium'
  tag gid: 'V-90187'
  tag rid: 'SV-100837r1_rule'
  tag stig_id: 'VRAU-TC-000940'
  tag gtitle: 'SRG-APP-000442-WSR-000182'
  tag fix_id: 'F-96929r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002422']
  tag nist: ['SC-8 (2)']
end
