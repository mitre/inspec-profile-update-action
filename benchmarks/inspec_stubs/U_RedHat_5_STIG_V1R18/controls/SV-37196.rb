control 'SV-37196' do
  title 'All run control scripts must have no extended ACLs.'
  desc 'If the startup files are writable by other users, they could modify the startup files to insert malicious commands into the startup files.'
  desc 'check', "Verify run control scripts have no extended ACLs.
# ls -lL /etc/rc* /etc/init.d
If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all <run control script with extended ACL>'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-37532r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22353'
  tag rid: 'SV-37196r1_rule'
  tag stig_id: 'GEN001590'
  tag gtitle: 'GEN001590'
  tag fix_id: 'F-32778r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
