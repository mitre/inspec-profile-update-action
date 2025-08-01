control 'SV-207611' do
  title 'The ESXi host SSH daemon must use DoD-approved encryption to protect the confidentiality of remote access sessions.'
  desc 'Approved algorithms should impart some level of confidence in their implementation. Limit the ciphers to those algorithms which are FIPS-approved. Counter (CTR) mode is also preferred over cipher-block chaining (CBC) mode.

Note: This does not imply FIPS 140-2 validation.'
  desc 'check', 'Only FIPS-approved ciphers should be used. To verify that only FIPS-approved ciphers are in use, run the following command from an SSH session connected to the ESXi host, or from the ESXi shell: 

# grep -i "^Ciphers" /etc/ssh/sshd_config

If there is no output or the output is not exactly "Ciphers aes256-ctr,aes192-ctr,aes128-ctr", this is a finding.'
  desc 'fix', 'Limit the ciphers to those algorithms which are FIPS-approved. Counter (CTR) mode is also preferred over cipher-block chaining (CBC) mode. 

From an SSH session connected to the ESXi host, or from the ESXi shell, add or correct the following line in "/etc/ssh/sshd_config": 

Ciphers aes256-ctr,aes192-ctr,aes128-ctr'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.5 ESXi'
  tag check_id: 'C-7866r766917_chk'
  tag severity: 'medium'
  tag gid: 'V-207611'
  tag rid: 'SV-207611r766919_rule'
  tag stig_id: 'ESXI-65-000010'
  tag gtitle: 'SRG-OS-000033-VMM-000140'
  tag fix_id: 'F-7866r766918_fix'
  tag 'documentable'
  tag legacy: ['V-93967', 'SV-104053']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
