control 'SV-38751' do
  title 'The /etc/ftpaccess.ctl file must be owned by root.'
  desc 'If the ftpaccess.ctl  file is not owned by root, an unauthorized user may modify the file to allow unauthorized access to change the file.   Unauthorized modification could result in Denial of Service to authorized FTP users or permit unauthorized access to system information.'
  desc 'check', 'Check the ownership of the /etc/ftpaccess.ctl file.

# ls -l /etc/ftpaccess.ctl

If the ftpaccess.ctl file is not owned by root, this is a finding.'
  desc 'fix', 'Change the owner of the ftpaccess.ctl file to root.

# chown root /etc/ftpaccess.ctl'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37820r1_chk'
  tag severity: 'medium'
  tag gid: 'V-29520'
  tag rid: 'SV-38751r1_rule'
  tag stig_id: 'GEN000000-AIX0320'
  tag gtitle: 'GEN000000-AIX0320'
  tag fix_id: 'F-33078r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
