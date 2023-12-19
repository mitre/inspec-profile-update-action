control 'SV-227860' do
  title 'The ftpusers file must not have an extended ACL.'
  desc 'Excessive permissions on the ftpusers file could permit unauthorized modification.  Unauthorized modification could result in Denial of Service to authorized FTP users or permit unauthorized users to access the FTP service.'
  desc 'check', 'Check the permissions of the /etc/ftpd/ftpusers file.
# ls -lL /etc/ftpd/ftpusers
If the permissions include a "+", the file has an extended ACL and this is a finding.'
  desc 'fix', 'Remove the extended ACL from the file.
# chmod A- /etc/ftpd/ftpusers'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30022r489973_chk'
  tag severity: 'medium'
  tag gid: 'V-227860'
  tag rid: 'SV-227860r603266_rule'
  tag stig_id: 'GEN004950'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-30010r489974_fix'
  tag 'documentable'
  tag legacy: ['V-22445', 'SV-26707']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
