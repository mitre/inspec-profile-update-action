control 'SV-255961' do
  title 'The Arista network device must be configured to implement cryptographic mechanisms using a FIPS 140-2 approved algorithm to protect the confidentiality of remote maintenance sessions.'
  desc 'This requires the use of secure protocols instead of their unsecured counterparts, such as SSH instead of telnet, SCP instead of FTP, and HTTPS instead of HTTP. If unsecured protocols (lacking cryptographic mechanisms) are used for sessions, the contents of those sessions will be susceptible to eavesdropping, potentially putting sensitive data (including administrator passwords) at risk of compromise and potentially allowing hijacking of maintenance sessions.'
  desc 'check', 'Validate that a FIPS validated SSH encryption algorithm is selected.

NOTE: AES-CBC algorithms have been considered compromised and are no longer recommended for cryptographic algorithms. AES-CTR and AES-GCM are both superior algorithms and are recommended.

sh run | section management ssh
cipher aes256-ctr aes512-ctr aes128-ctr

If the Arista network device is not configured to implement cryptographic mechanisms to protect the confidentiality of remote maintenance sessions using a FIPS 140-2 approved algorithm, this is a finding.'
  desc 'fix', 'Configure the Arista network device to use FIPS-approved algorithms to protect the confidentiality of remote maintenance sessions.

switch(config)#management ssh
switch(config-mgmt-ssh)#cipher aes256-ctr aes512-ctr aes128-ctr'
  impact 0.7
  ref 'DPMS Target Arista MLS EOS 4.2x NDM'
  tag check_id: 'C-59637r882223_chk'
  tag severity: 'high'
  tag gid: 'V-255961'
  tag rid: 'SV-255961r882225_rule'
  tag stig_id: 'ARST-ND-000700'
  tag gtitle: 'SRG-APP-000412-NDM-000331'
  tag fix_id: 'F-59580r882224_fix'
  tag 'documentable'
  tag cci: ['CCI-003123']
  tag nist: ['MA-4 (6)']
end
