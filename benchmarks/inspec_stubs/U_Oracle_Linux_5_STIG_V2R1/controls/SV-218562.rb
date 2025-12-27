control 'SV-218562' do
  title 'The ftpusers file must not have an extended ACL.'
  desc 'Excessive permissions on the ftpusers file could permit unauthorized modification. Unauthorized modification could result in Denial of Service to authorized FTP users or permit unauthorized users to access the FTP service.'
  desc 'check', "Check the permissions of the /etc/ftpusers file. 
# ls -lL /etc/ftpusers /etc/vsftpd.ftpusers /etc/vsftpd/ftpusers

If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /etc/ftpusers /etc/vsftpd.ftpusers /etc/vsftpd/ftpusers'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20037r562780_chk'
  tag severity: 'medium'
  tag gid: 'V-218562'
  tag rid: 'SV-218562r603259_rule'
  tag stig_id: 'GEN004950'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-20035r562781_fix'
  tag 'documentable'
  tag legacy: ['V-22445', 'SV-63083']
  tag cci: ['CCI-000225', 'CCI-001090']
  tag nist: ['AC-6', 'SC-4']
end
