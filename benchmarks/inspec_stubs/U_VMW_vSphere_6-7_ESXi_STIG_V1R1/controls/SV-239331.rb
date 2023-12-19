control 'SV-239331' do
  title 'The ESXi host SSH daemon must be configured to only use FIPS 140-2 approved ciphers.'
  desc 'Approved algorithms should impart some level of confidence in their implementation. These are also required for compliance.'
  desc 'check', 'Verify that only FIPS-approved ciphers are used by running the following command: 

# grep -i "^Ciphers" /etc/ssh/sshd_config

If there is no output, or the output is not exactly "Ciphers aes128-ctr,aes192-ctr,aes256-ctr", this is a finding.'
  desc 'fix', 'Limit the ciphers to algorithms that are FIPS approved. Counter (CTR) mode is also preferred over cipher-block chaining (CBC) mode. 

Add or correct the following line in "/etc/ssh/sshd_config": 

Ciphers aes128-ctr,aes192-ctr,aes256-ctr'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 ESXi'
  tag check_id: 'C-42564r674920_chk'
  tag severity: 'medium'
  tag gid: 'V-239331'
  tag rid: 'SV-239331r674922_rule'
  tag stig_id: 'ESXI-67-100010'
  tag gtitle: 'SRG-OS-000478-VMM-001980'
  tag fix_id: 'F-42523r674921_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
