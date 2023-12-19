control 'SV-37542' do
  title 'The ftpusers file must have mode 0640 or less permissive.'
  desc 'Excessive permissions on the ftpusers file could permit unauthorized modification. Unauthorized modification could result in Denial of Service to authorized FTP users or permit unauthorized users to access the FTP service.'
  desc 'check', 'Check the permissions of the ftpusers file.

Procedure:
For gssftp:
# ls -l /etc/ftpusers

For vsftp:
# ls -l /etc/vsftpd.ftpusers /etc/vsftpd/ftpusers
If the ftpusers file has a mode more permissive than 0640, this is a finding.'
  desc 'fix', 'Change the mode of the ftpusers file to 0640.

Procedure:
For gssftp:
# chmod 0640 /etc/ftpusers

For vsftp:
# chmod 0640 /etc/vsftpd.ftpusers /etc/vsftpd/ftpusers'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36199r1_chk'
  tag severity: 'medium'
  tag gid: 'V-843'
  tag rid: 'SV-37542r1_rule'
  tag stig_id: 'GEN004940'
  tag gtitle: 'GEN004940'
  tag fix_id: 'F-31457r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
