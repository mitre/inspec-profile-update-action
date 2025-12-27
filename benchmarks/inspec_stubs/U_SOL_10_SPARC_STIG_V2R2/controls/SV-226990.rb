control 'SV-226990' do
  title 'The SSH client must be configured to not use CBC-based ciphers.'
  desc 'The Cipher-Block Chaining (CBC) mode of encryption as implemented in the SSHv2 protocol is vulnerable to chosen plain text attacks and must not be used.'
  desc 'check', "Check the SSH client configuration for allowed ciphers.
# grep -i ciphers /etc/ssh/ssh_config | grep -v '^#' 
If no lines are returned, or the returned ciphers list contains any cipher ending with cbc, this is a finding."
  desc 'fix', 'Edit /etc/ssh/ssh_config and add or edit the "Ciphers" line.  Only include ciphers that start with "3des" or "aes" and do not contain "cbc".  For the list of available ciphers for the particular version of your software, consult the ssh_config manpage.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29152r485309_chk'
  tag severity: 'medium'
  tag gid: 'V-226990'
  tag rid: 'SV-226990r603265_rule'
  tag stig_id: 'GEN005511'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29140r485310_fix'
  tag 'documentable'
  tag legacy: ['V-22462', 'SV-26755']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
