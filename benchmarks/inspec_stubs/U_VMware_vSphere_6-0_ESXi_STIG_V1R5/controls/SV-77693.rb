control 'SV-77693' do
  title 'The SSH daemon must be configured to only use Message Authentication Codes (MACs) employing FIPS 140-2 approved cryptographic hash algorithms.'
  desc 'DoD information systems are required to use FIPS 140-2 approved cryptographic hash functions.

Note: This does not imply FIPS 140-2 certification.'
  desc 'check', 'To verify the MACs setting, run the following command: 

# grep -i "^MACs" /etc/ssh/sshd_config

If there is no output or the output is not exactly "MACs hmac-sha1,hmac-sha2-256,hmac-sha2-512", this is a finding.'
  desc 'fix', 'To set the MACs setting, add or correct the following line in "/etc/ssh/sshd_config":

MACs hmac-sha1,hmac-sha2-256,hmac-sha2-512'
  impact 0.5
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-63937r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63203'
  tag rid: 'SV-77693r1_rule'
  tag stig_id: 'ESXI-06-000017'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-69121r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
