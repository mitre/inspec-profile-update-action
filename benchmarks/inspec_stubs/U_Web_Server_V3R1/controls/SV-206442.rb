control 'SV-206442' do
  title 'The web server must maintain the confidentiality and integrity of information during reception.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during reception, including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

Protecting the confidentiality and integrity of received information requires that application servers take measures to employ approved cryptography in order to protect the information during transmission over the network. This is usually achieved through the use of Transport Layer Security (TLS), SSL VPN, or IPsec tunnel. 

The web server must utilize approved encryption when receiving transmitted data.'
  desc 'check', 'Review web server configuration to determine if the server is using a transmission method that maintains the confidentiality and integrity of information during reception.

If a transmission method is not being used that maintains the confidentiality and integrity of the data during reception, this is a finding.'
  desc 'fix', 'Configure the web server to utilize a transmission method that maintains the confidentiality and integrity of information during reception.'
  impact 0.5
  ref 'DPMS Target Web Server'
  tag check_id: 'C-6703r377918_chk'
  tag severity: 'medium'
  tag gid: 'V-206442'
  tag rid: 'SV-206442r855063_rule'
  tag stig_id: 'SRG-APP-000442-WSR-000182'
  tag gtitle: 'SRG-APP-000442'
  tag fix_id: 'F-6703r377919_fix'
  tag 'documentable'
  tag legacy: ['SV-70269', 'V-56015']
  tag cci: ['CCI-002422']
  tag nist: ['SC-8 (2)']
end
