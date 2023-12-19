control 'SV-77679' do
  title 'The VMM must use DoD-approved encryption to protect the confidentiality of remote access sessions.'
  desc 'Approved algorithms should impart some level of confidence in their implementation. These are also required for compliance.

Note: This does not imply FIPS 140-2 certification.'
  desc 'check', 'Only FIPS-approved ciphers should be used. To verify that only FIPS-approved ciphers are in use, run the following command: 

# grep -i "^Ciphers" /etc/ssh/sshd_config

If there is no output or the output is not "Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,aes192-cbc,aes256-cbc", or a subset of this list, this is a finding.'
  desc 'fix', 'Limit the ciphers to those algorithms which are FIPS-approved. Counter (CTR) mode is also preferred over cipher-block chaining (CBC) mode. 

Add or correct the following line in "/etc/ssh/sshd_config": 

Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,aes192-cbc,aes256-cbc'
  impact 0.5
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-63923r4_chk'
  tag severity: 'medium'
  tag gid: 'V-63189'
  tag rid: 'SV-77679r3_rule'
  tag stig_id: 'ESXI-06-000010'
  tag gtitle: 'SRG-OS-000033-VMM-000140'
  tag fix_id: 'F-69107r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
