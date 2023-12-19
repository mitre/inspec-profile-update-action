control 'SV-77473' do
  title 'Applications used for nonlocal maintenance sessions must implement cryptographic mechanisms to protect the confidentiality of nonlocal maintenance and diagnostic communications.'
  desc 'This requires the use of secure protocols instead of their unsecured counterparts, such as SSH instead of telnet, SCP instead of FTP, and HTTPS instead of HTTP. If unsecured protocols (lacking cryptographic mechanisms) are used for sessions, the contents of those sessions will be susceptible to eavesdropping, potentially putting sensitive data (including administrator passwords) at risk of compromise and potentially allowing hijacking of maintenance sessions.'
  desc 'check', 'Verify that RiOS is configured to implement cryptographic mechanisms to protect the confidentiality of nonlocal maintenance and diagnostic communications.

Navigate to the device CLI
Type: enable
Type: show configuration full
Verify that "no telnet-server enable" is in the configuration
Verify that "ssh server enable" is set in the configuration
Verify that "web enable" is in the configuration
Verify that "no web http enable" is in the configuration
Verify that "web https enable" is in the configuration

If any one of the above settings is missing from the configuration, this is a finding.'
  desc 'fix', 'Configure RiOS to implement cryptographic mechanisms to protect the confidentiality of nonlocal maintenance and diagnostic communications.

Navigate to the device CLI
Type: enable
Type: config t
Type: no telnet-server enable
Type: ssh server enable
Type: ssh server allowed-cyphers aes128-cbc, 3des-cbc,aes192-cbc,aes256-cbc,aes128-ctr,aes192-ctr,aes256-ctr
Type: web enable
Type: no web http enable
Type: web https enable
Type: write memory
Type: exit
Type: exit'
  impact 0.5
  ref 'DPMS Target Riverbed SteelHead CX Version 8 NDM'
  tag check_id: 'C-63735r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62983'
  tag rid: 'SV-77473r1_rule'
  tag stig_id: 'RICX-DM-000135'
  tag gtitle: 'SRG-APP-000412-NDM-000331'
  tag fix_id: 'F-68901r1_fix'
  tag 'documentable'
  tag cci: ['CCI-003123']
  tag nist: ['MA-4 (6)']
end
