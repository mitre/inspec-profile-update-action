control 'SV-38345' do
  title 'All global initialization files must not have extended ACLs.'
  desc "Global initialization files are used to configure the user's shell environment upon login.  Malicious modification of these files could compromise accounts upon logon."
  desc 'check', 'Check global initialization files for extended ACLs.
# ls -lL /etc/profile /etc/bashrc /etc/csh.login /etc/csh.cshrc /etc/environment /etc/.login /etc/security/environ

If the permissions include a "+", the file has an extended ACL, this is a finding.'
  desc 'fix', 'Remove the optional ACL from the file.
# chacl -z [global initialization file with extended ACL]'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36384r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22356'
  tag rid: 'SV-38345r1_rule'
  tag stig_id: 'GEN001730'
  tag gtitle: 'GEN001730'
  tag fix_id: 'F-31723r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
