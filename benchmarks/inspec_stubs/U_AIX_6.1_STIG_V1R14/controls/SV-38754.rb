control 'SV-38754' do
  title 'The /etc/ftpaccess.ctl file must not have an extended ACL.'
  desc 'Excessive permissions on the ftpaccess.ctl file could permit unauthorized modification. Unauthorized modification could result in Denial of Service to authorized FTP users or permit unauthorized access to system information.'
  desc 'check', 'Check the permissions of the /etc/ftpaccess.ctl file.

#aclget /etc/ftpaccess.ctl 

Check if extended permissions are disabled.

If extended permissions are not disabled,  this is a finding.'
  desc 'fix', 'Remove the extended ACL from the /etc/ftpaccess.ctl file. 

#acledit /etc/ftpaccess.ctl 
Disable extended permissions.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37823r1_chk'
  tag severity: 'medium'
  tag gid: 'V-29523'
  tag rid: 'SV-38754r1_rule'
  tag stig_id: 'GEN000000-AIX0350'
  tag gtitle: 'GEN000000-AIX0350'
  tag fix_id: 'F-33081r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
