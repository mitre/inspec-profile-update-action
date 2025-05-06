control 'SV-226545' do
  title 'All global initialization files must not have extended ACLs.'
  desc "Global initialization files are used to configure the user's shell environment upon login.  Malicious modification of these files could compromise accounts upon logon."
  desc 'check', 'Check global initialization files for extended ACLs.
# ls -lL /etc/profile /etc/bashrc /etc/csh.login /etc/csh.cshrc /etc/environment /etc/.login /etc/security/environ
If the permissions on an existing file include a "+", the file has an extended ACL, this is a finding.'
  desc 'fix', 'Remove the extended ACL from the file.
# chmod A- [global initialization file with extended ACL]'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28706r483032_chk'
  tag severity: 'medium'
  tag gid: 'V-226545'
  tag rid: 'SV-226545r603265_rule'
  tag stig_id: 'GEN001730'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28694r483033_fix'
  tag 'documentable'
  tag legacy: ['SV-26471', 'V-22356']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
