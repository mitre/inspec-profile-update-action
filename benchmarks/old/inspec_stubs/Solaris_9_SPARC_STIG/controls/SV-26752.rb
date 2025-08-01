control 'SV-26752' do
  title 'The SSH daemon must be configured to not use Cipher-Block Chaining (CBC) ciphers.'
  desc 'The Cipher-Block Chaining (CBC) mode of encryption as implemented in the SSHv2 protocol is vulnerable to chosen plain text attacks and must not be used.'
  desc 'fix', 'Edit /etc/ssh/sshd_config and add or edit the "Ciphers" line.  Only include ciphers that start with "3des" or "aes" and do not contain "cbc".  For the list of available ciphers for the particular version of your software, consult the sshd_config manpage.

Restart the SSH daemon.'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-22459'
  tag rid: 'SV-26752r2_rule'
  tag stig_id: 'GEN005506'
  tag gtitle: 'GEN005506'
  tag fix_id: 'F-24001r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
