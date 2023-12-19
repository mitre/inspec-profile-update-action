control 'SV-226525' do
  title 'The /etc/shadow file must not have an extended ACL.'
  desc 'The /etc/shadow file contains the list of local system accounts.  It is vital to system security and must be protected from unauthorized modification.  The file also contains password hashes which must not be accessible to users other than root.'
  desc 'check', "Verify /etc/shadow has no extended ACL.
# ls -lL /etc/shadow

If the permissions include a '+', the file has an extended ACL and this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# chmod A- /etc/shadow'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28686r482963_chk'
  tag severity: 'medium'
  tag gid: 'V-226525'
  tag rid: 'SV-226525r603265_rule'
  tag stig_id: 'GEN001430'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28674r482964_fix'
  tag 'documentable'
  tag legacy: ['SV-26440', 'V-22340']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
