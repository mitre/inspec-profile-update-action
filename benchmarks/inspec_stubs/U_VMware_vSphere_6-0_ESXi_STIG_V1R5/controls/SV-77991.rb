control 'SV-77991' do
  title 'The SSH daemon must be configured to only use FIPS 140-2 approved ciphers.'
  desc 'Approved algorithms should impart some level of confidence in their implementation. These are also required for compliance.

Note: That this does not imply FIPS 140-2 certification.'
  desc 'check', 'Only FIPS-approved ciphers should be used. To verify that only FIPS-approved ciphers are in use, run the following command: 

# grep -i "^Ciphers" /etc/ssh/sshd_config

If there is no output or the output is not exactly "Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,aes192-cbc,aes256-cbc", this is a finding.'
  desc 'fix', 'Limit the ciphers to those algorithms which are FIPS-approved. Counter (CTR) mode is also preferred over cipher-block chaining (CBC) mode. 

Add or correct the following line in "/etc/ssh/sshd_config": 

Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,aes192-cbc,aes256-cbc'
  impact 0.5
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-64251r2_chk'
  tag severity: 'medium'
  tag gid: 'V-63501'
  tag rid: 'SV-77991r2_rule'
  tag stig_id: 'ESXI-06-100010'
  tag gtitle: 'SRG-OS-000478-VMM-001980'
  tag fix_id: 'F-69431r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
