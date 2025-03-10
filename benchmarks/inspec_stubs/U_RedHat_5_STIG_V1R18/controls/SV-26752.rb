control 'SV-26752' do
  title 'The SSH daemon must be configured to not use Cipher-Block Chaining (CBC) ciphers.'
  desc 'The Cipher-Block Chaining (CBC) mode of encryption as implemented in the SSHv2 protocol is vulnerable to chosen plain text attacks and must not be used.'
  desc 'check', "Check the SSH daemon configuration for allowed ciphers.
# grep -i ciphers /etc/ssh/sshd_config | grep -v '^#' 
If no lines are returned, or the returned ciphers list contains any cipher ending with cbc, this is a finding."
  desc 'fix', 'Edit /etc/ssh/sshd_config and add or edit the "Ciphers" line.  Only include ciphers that start with "3des" or "aes" and do not contain "cbc".  For the list of available ciphers for the particular version of your software, consult the sshd_config manpage.

Restart the SSH daemon.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-27761r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22459'
  tag rid: 'SV-26752r2_rule'
  tag stig_id: 'GEN005506'
  tag gtitle: 'GEN005506'
  tag fix_id: 'F-24001r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
