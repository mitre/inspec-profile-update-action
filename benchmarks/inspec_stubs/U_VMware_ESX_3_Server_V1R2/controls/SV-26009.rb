control 'SV-26009' do
  title 'Local initialization files must not have extended ACLs.'
  desc "Local initialization files are used to configure the user's shell environment upon login.  Malicious modification of these files could compromise accounts upon logon."
  desc 'check', 'Check user home directories for local initialization files with extended ACLs.
# cut -d : -f 6 /etc/passwd | xargs -n1 -IDIR ls -alL DIR/.login DIR/.cshrc DIR/.logout DIR/.profile DIR/.bash_profile DIR/.bashrc DIR/.bash_logout DIR/.env DIR/.dtprofile DIR/.dispatch DIR/.emacs DIR/.exrc

If the permissions include a "+", the file has an extended ACL, this is a finding.'
  desc 'fix', 'Remove the extended ACL from the local initialization file(s).'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27544r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22362'
  tag rid: 'SV-26009r1_rule'
  tag stig_id: 'GEN001890'
  tag gtitle: 'GEN001890'
  tag fix_id: 'F-26203r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
