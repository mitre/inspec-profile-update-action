control 'SV-202118' do
  title 'The network device must be configured to implement cryptographic mechanisms using a FIPS 140-2 approved algorithm to protect the confidentiality of remote maintenance sessions'
  desc 'This requires the use of secure protocols instead of their unsecured counterparts, such as SSH instead of telnet, SCP instead of FTP, and HTTPS instead of HTTP. If unsecured protocols (lacking cryptographic mechanisms) are used for sessions, the contents of those sessions will be susceptible to eavesdropping, potentially putting sensitive data (including administrator passwords) at risk of compromise and potentially allowing hijacking of maintenance sessions.'
  desc 'check', 'Review the network device configuration to determine if cryptographic mechanisms are implemented using a FIPS 140-2 approved algorithm to protect the confidentiality of remote maintenance sessions 

If the network device is not configured to implement cryptographic mechanisms to protect the confidentiality of remote maintenance sessions using a FIPS 140-2 approved algorithm, this is a finding.'
  desc 'fix', 'Configure the network device to implement cryptographic mechanisms to protect the confidentiality of remote maintenance sessions using a FIPS 140-2 approved algorithm.'
  impact 0.7
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2244r382034_chk'
  tag severity: 'high'
  tag gid: 'V-202118'
  tag rid: 'SV-202118r879785_rule'
  tag stig_id: 'SRG-APP-000412-NDM-000331'
  tag gtitle: 'SRG-APP-000412'
  tag fix_id: 'F-2245r382035_fix'
  tag 'documentable'
  tag legacy: ['SV-69513', 'V-55267']
  tag cci: ['CCI-003123']
  tag nist: ['MA-4 (6)']
end
