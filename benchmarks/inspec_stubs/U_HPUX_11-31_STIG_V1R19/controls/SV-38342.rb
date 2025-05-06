control 'SV-38342' do
  title 'All run control scripts must have no extended ACLs.'
  desc 'If the startup files are writable by other users, they could modify the startup files to insert malicious commands into the startup files.'
  desc 'check', "Check that run control scripts have no extended ACLs.
# ls -lLa /sbin/init.d/[a-z,A-Z,0-9]*

If the permissions include a '+' the file has an extended ACL, this is a finding."
  desc 'fix', 'Remove the optional ACL from the file.
# chacl -z [run control script with extended ACL]'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36362r2_chk'
  tag severity: 'medium'
  tag gid: 'V-22353'
  tag rid: 'SV-38342r1_rule'
  tag stig_id: 'GEN001590'
  tag gtitle: 'GEN001590'
  tag fix_id: 'F-31699r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
