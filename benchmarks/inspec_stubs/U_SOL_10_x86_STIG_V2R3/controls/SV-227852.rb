control 'SV-227852' do
  title 'Unencrypted FTP must not be used on the system.'
  desc 'FTP is typically unencrypted and, therefore, presents confidentiality and integrity risks.  FTP may be protected by encryption in certain cases, such as when used in a Kerberos environment.   SFTP and FTPS are encrypted alternatives to FTP.'
  desc 'check', 'Perform the following to determine if unencrypted FTP is enabled.

# svcs ftp

If FTP is enabled, ask the SA if it is encrypted.  If it is not, this is a finding.'
  desc 'fix', '# svcadm disable ftp'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30014r489949_chk'
  tag severity: 'medium'
  tag gid: 'V-227852'
  tag rid: 'SV-227852r603266_rule'
  tag stig_id: 'GEN004800'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-30002r489950_fix'
  tag 'documentable'
  tag legacy: ['V-12010', 'SV-28635']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
