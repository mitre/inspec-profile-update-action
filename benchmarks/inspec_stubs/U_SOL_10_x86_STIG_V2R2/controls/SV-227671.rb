control 'SV-227671' do
  title 'All global initialization files must not have extended ACLs.'
  desc "Global initialization files are used to configure the user's shell environment upon login.  Malicious modification of these files could compromise accounts upon logon."
  desc 'check', 'Check global initialization files for extended ACLs.
# ls -lL /etc/profile /etc/bashrc /etc/csh.login /etc/csh.cshrc /etc/environment /etc/.login /etc/security/environ
If the permissions on an existing file include a "+", the file has an extended ACL, this is a finding.'
  desc 'fix', 'Remove the extended ACL from the file.
# chmod A- [global initialization file with extended ACL]'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29833r488582_chk'
  tag severity: 'medium'
  tag gid: 'V-227671'
  tag rid: 'SV-227671r603266_rule'
  tag stig_id: 'GEN001730'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29821r488583_fix'
  tag 'documentable'
  tag legacy: ['V-22356', 'SV-26471']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
