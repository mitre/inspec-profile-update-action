control 'SV-218340' do
  title 'Local initialization files must not have extended ACLs.'
  desc "Local initialization files are used to configure the user's shell environment upon login.  Malicious modification of these files could compromise accounts upon logon."
  desc 'check', "Check user home directories for local initialization files with extended ACLs.
# cut -d : -f 6 /etc/passwd | xargs -n1 -IDIR ls -alL DIR/.bashrc DIR/.bash_login DIR/.bash_logout DIR/.bash_profile DIR/.cshrc DIR/.kshrc DIR/.login DIR/.logout DIR/.profile DIR/.env DIR/.dtprofile DIR/.dispatch DIR/.emacs DIR/.exrc

If the permissions include a '+', the file has an extended ACL. 

If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all <local initialization file with extended ACL>'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19815r569011_chk'
  tag severity: 'medium'
  tag gid: 'V-218340'
  tag rid: 'SV-218340r603259_rule'
  tag stig_id: 'GEN001890'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19813r569012_fix'
  tag 'documentable'
  tag legacy: ['V-22362', 'SV-63537']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
