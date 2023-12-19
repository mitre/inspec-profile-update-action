control 'SV-38734' do
  title 'All global initialization files must not have extended ACLs.'
  desc "Global initialization files are used to configure the user's shell environment upon login.  Malicious modification of these files could compromise accounts upon logon."
  desc 'check', 'Check global initialization files for extended ACLs.

Procedure:
#aclget  /etc/profile /etc/bashrc /etc/csh.login /etc/csh.cshrc /etc/environment /etc/.login /etc/security/environ /etc/security/.profile

Check if extended permissions are disabled.  If extended permissions are not disabled,  this is a finding.'
  desc 'fix', 'Remove the extended ACL from the global initialization file(s) and disable extended permissions.

#acledit <directory>/<file>'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37159r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22356'
  tag rid: 'SV-38734r1_rule'
  tag stig_id: 'GEN001730'
  tag gtitle: 'GEN001730'
  tag fix_id: 'F-32449r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
