control 'SV-38753' do
  title 'The /etc/ftpaccess.ctl file must have mode 0640 or less permissive.'
  desc 'Excessive permissions on the ftpaccess.ctl file could permit unauthorized modification. Unauthorized modification could result in Denial of Service to authorized FTP users or permit unauthorized access to system information.'
  desc 'check', 'Check the permissions of the /etc/ftpaccess.ctl file.

# ls -l /etc/ftpaccess.ctl

If the ftpaccess.ctl file has a mode more permissive than 0640, this is a finding.'
  desc 'fix', 'Change the mode of the /etc/ftpaccess.ctl file to 0640.

# chmod 0640 /etc/ftpaccess.ctl'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37822r1_chk'
  tag severity: 'medium'
  tag gid: 'V-29522'
  tag rid: 'SV-38753r1_rule'
  tag stig_id: 'GEN000000-AIX0340'
  tag gtitle: 'GEN000000-AIX0340'
  tag fix_id: 'F-33080r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
