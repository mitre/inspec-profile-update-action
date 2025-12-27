control 'SV-38739' do
  title 'Local initialization files must not have extended ACLs.'
  desc "Local initialization files are used to configure the user's shell environment upon login.  Malicious modification of these files could compromise accounts upon logon."
  desc 'check', 'Check user home directories for local initialization files with extended ACLs.

Procedure:
# cat /etc/passwd | cut -f 6,6 -d ":" | xargs -n1 -IDIR ls -le DIR/.login DIR/.cshrc DIR/.logout DIR/.profile DIR/.bash_profile DIR/.bashrc DIR/.bash_logout DIR/.env DIR/.dtprofile DIR/.dispatch DIR/.emacs DIR/.exrc

Procedure:
#aclget <directory>/<file> and check if extended permissions are disabled.  If extended permissions are not disabled,  this is a finding.'
  desc 'fix', 'Remove the extended ACL from the local initialization file(s) and disable extended permissions.

#acledit <directory>/<file>'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37172r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22362'
  tag rid: 'SV-38739r1_rule'
  tag stig_id: 'GEN001890'
  tag gtitle: 'GEN001890'
  tag fix_id: 'F-32454r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
