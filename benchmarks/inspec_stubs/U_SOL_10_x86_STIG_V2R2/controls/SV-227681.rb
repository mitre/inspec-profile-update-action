control 'SV-227681' do
  title 'Local initialization files must not have extended ACLs.'
  desc "Local initialization files are used to configure the user's shell environment upon login.  Malicious modification of these files could compromise accounts upon logon."
  desc 'check', 'Check user home directories for local initialization files with extended ACLs.
# cut -d : -f 6 /etc/passwd | xargs -n1 -IDIR ls -alL DIR/.login DIR/.cshrc DIR/.logout DIR/.profile DIR/.bash_profile DIR/.bashrc DIR/.bash_logout DIR/.env DIR/.dtprofile DIR/.dispatch DIR/.emacs DIR/.exrc

If the permissions include a "+", the file has an extended ACL, this is a finding.'
  desc 'fix', 'Remove the extended ACL from the file.
# chmod A- [local initialization file with extended ACL]'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29843r488624_chk'
  tag severity: 'medium'
  tag gid: 'V-227681'
  tag rid: 'SV-227681r603266_rule'
  tag stig_id: 'GEN001890'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29831r488625_fix'
  tag 'documentable'
  tag legacy: ['V-22362', 'SV-26484']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
