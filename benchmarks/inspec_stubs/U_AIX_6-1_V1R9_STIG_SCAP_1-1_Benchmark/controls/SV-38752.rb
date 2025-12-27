control 'SV-38752' do
  title 'The /etc/ftpaccess.ctl file must be group-owned by bin, sys, or system.'
  desc 'If the ftpaccess.ctl file is not group-owned by a system group, an unauthorized user may modify the file to allow unauthorized access to modify the file. Unauthorized modification could result in Denial of Service to authorized FTP users or permit unauthorized access to system information.'
  desc 'fix', 'Change the group owner of the /etc/ftpaccess.ctl file.

# chgrp system /etc/ftpaccess.ctl'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag severity: 'medium'
  tag gid: 'V-29521'
  tag rid: 'SV-38752r1_rule'
  tag stig_id: 'GEN000000-AIX0330'
  tag gtitle: 'GEN000000-AIX0330'
  tag fix_id: 'F-33079r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
