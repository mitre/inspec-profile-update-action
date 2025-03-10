control 'SV-218659' do
  title 'The /etc/news/passwd.nntp file must not have an extended ACL.'
  desc 'Extended ACLs may provide excessive permissions on the  /etc/news/passwd.nntp file, which may permit unauthorized  access or modification to the NNTP configuration.'
  desc 'check', "Check the permissions of the file.
# ls -lL /etc/news/passwd.nntp
If the mode includes a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /etc/news/passwd.nntp'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20134r556175_chk'
  tag severity: 'medium'
  tag gid: 'V-218659'
  tag rid: 'SV-218659r603259_rule'
  tag stig_id: 'GEN006330'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20132r556176_fix'
  tag 'documentable'
  tag legacy: ['V-22505', 'SV-63835']
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
