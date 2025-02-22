control 'SV-207618' do
  title 'The ESXi host SSH daemon must be configured to only use Message Authentication Codes (MACs) employing FIPS 140-2 approved cryptographic hash algorithms.'
  desc 'DoD information systems are required to use FIPS 140-2 approved cryptographic hash functions.'
  desc 'check', 'From an SSH session connected to the ESXi host, or from the ESXi shell, run the following command:

# grep -i "^MACs" /etc/ssh/sshd_config

If there is no output or the output is not exactly "MACs hmac-sha1,hmac-sha2-256,hmac-sha2-512", this is a finding.'
  desc 'fix', 'From an SSH session connected to the ESXi host, or from the ESXi shell, add or correct the following line in "/etc/ssh/sshd_config":

MACs hmac-sha1,hmac-sha2-256,hmac-sha2-512'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.5 ESXi'
  tag check_id: 'C-7873r364253_chk'
  tag severity: 'medium'
  tag gid: 'V-207618'
  tag rid: 'SV-207618r388482_rule'
  tag stig_id: 'ESXI-65-000017'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-7873r364254_fix'
  tag 'documentable'
  tag legacy: ['V-93981', 'SV-104067']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
