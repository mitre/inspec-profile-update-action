control 'SV-37824' do
  title 'The SSH daemon must be configured to only use FIPS 140-2 approved ciphers.'
  desc 'DoD information systems are required to use FIPS 140-2 approved ciphers.  SSHv2 ciphers meeting this requirement are 3DES and AES.'
  desc 'fix', 'Edit the SSH daemon configuration and remove any ciphers not starting with "3des" or "aes" and remove any ciphers ending with "cbc". If necessary, add a "Ciphers" line.

Ciphers aes256-ctr,aes192-ctr,aes128-ctr

Restart the SSH daemon.
# /sbin/service sshd restart'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22458'
  tag rid: 'SV-37824r3_rule'
  tag stig_id: 'GEN005505'
  tag gtitle: 'GEN005505'
  tag fix_id: 'F-32293r4_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
