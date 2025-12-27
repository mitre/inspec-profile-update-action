control 'SV-204820' do
  title 'The application server must maintain the confidentiality and integrity of information during reception.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during reception, including, for example, during aggregation, at protocol transformation points, and during packing/unpacking.  These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

Protecting the confidentiality and integrity of received information requires that application servers take measures to employ approved cryptography in order to protect the information during transmission over the network. This is usually achieved through the use of Transport Layer Security (TLS), SSL VPN, or IPSEC tunnel.

The application server must utilize approved encryption when receiving transmitted data.'
  desc 'check', 'Review application server configuration to determine if the server is using a transmission method that maintains the confidentiality and integrity of information during reception.

If a transmission method is not being used that maintains the confidentiality and integrity of the data during reception, this is a finding.'
  desc 'fix', 'Configure the application server to utilize a transmission method that maintains the confidentiality and integrity of information during reception.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4940r283101_chk'
  tag severity: 'medium'
  tag gid: 'V-204820'
  tag rid: 'SV-204820r850872_rule'
  tag stig_id: 'SRG-APP-000442-AS-000259'
  tag gtitle: 'SRG-APP-000442'
  tag fix_id: 'F-4940r283102_fix'
  tag 'documentable'
  tag legacy: ['V-57539', 'SV-71815']
  tag cci: ['CCI-002422']
  tag nist: ['SC-8 (2)']
end
