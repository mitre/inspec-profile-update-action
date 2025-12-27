control 'SV-37544' do
  title 'The ftpusers file must not have an extended ACL.'
  desc 'Excessive permissions on the ftpusers file could permit unauthorized modification. Unauthorized modification could result in Denial of Service to authorized FTP users or permit unauthorized users to access the FTP service.'
  desc 'check', "Check the permissions of the /etc/ftpusers file. 
# ls -lL /etc/ftpusers /etc/vsftpd.ftpusers /etc/vsftpd/ftpusers
If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /etc/ftpusers /etc/vsftpd.ftpusers /etc/vsftpd/ftpusers'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36200r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22445'
  tag rid: 'SV-37544r1_rule'
  tag stig_id: 'GEN004950'
  tag gtitle: 'GEN004950'
  tag fix_id: 'F-31459r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
