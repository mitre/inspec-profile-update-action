control 'SV-35193' do
  title 'The SSH client must be configured to not use Cipher-Block Chaining (CBC) based ciphers.'
  desc 'The CBC mode of encryption as implemented in the SSHv2 protocol is vulnerable to chosen plaintext attacks and must not be used.'
  desc 'fix', 'Edit the configuration file and remove any ciphers other than those with the "aes" prefix and the "-ctr" suffix.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-22462'
  tag rid: 'SV-35193r1_rule'
  tag stig_id: 'GEN005511'
  tag gtitle: 'GEN005511'
  tag fix_id: 'F-32008r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
