control 'SV-239931' do
  title 'The Cisco ASA must be configured to implement cryptographic mechanisms using a FIPS 140-2 approved algorithm to protect the confidentiality of remote maintenance sessions.'
  desc 'This requires the use of secure protocols instead of their unsecured counterparts, such as SSH instead of telnet, SCP instead of FTP, and HTTPS instead of HTTP. If unsecured protocols (lacking cryptographic mechanisms) are used for sessions, the contents of those sessions will be susceptible to eavesdropping, potentially putting sensitive data (including administrator passwords) at risk of compromise and potentially allowing hijacking of maintenance sessions.'
  desc 'check', 'Step 1: Verify FIPS mode is enabled as shown in the example below. 

fips enable

Step 2: Verify that only SSH is configured to only use FIPS-compliant ciphers and that Diffie-Hellman Group 14  is used for the key exchange as shown in the example below.

ssh version 2
ssh cipher encryption fips
ssh key-exchange group dh-group14-sha1

Note: The ASA only supports SSHv2.

If the ASA is not configured to implement cryptographic mechanisms to protect the confidentiality of remote maintenance sessions using a FIPS 140-2 approved algorithm, this is a finding.'
  desc 'fix', 'Step 1: Enable FIPS mode via the fips enable command.

Step 2: Configure SSH to only use FIPS-compliant ciphers and Diffie-Hellman Group 14 for the key exchange.

ASA(config)# ssh cipher encryption fips 
ASA(config)# ssh key-exchange group dh-group14-sha'
  impact 0.7
  ref 'DPMS Target Cisco ASA NDM'
  tag check_id: 'C-43164r666154_chk'
  tag severity: 'high'
  tag gid: 'V-239931'
  tag rid: 'SV-239931r851036_rule'
  tag stig_id: 'CASA-ND-001150'
  tag gtitle: 'SRG-APP-000412-NDM-000331'
  tag fix_id: 'F-43123r666155_fix'
  tag 'documentable'
  tag cci: ['CCI-003123']
  tag nist: ['MA-4 (6)']
end
