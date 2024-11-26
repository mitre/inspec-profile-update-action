control 'SV-208817' do
  title 'The /etc/passwd file must be group-owned by root.'
  desc 'The "/etc/passwd" file contains information about the users that are configured on the system. Protection of this file is critical for system security.'
  desc 'check', 'To check the group ownership of "/etc/passwd", run the command: 

$ ls -l /etc/passwd

If properly configured, the output should indicate the following group-owner. "root" 
If it does not, this is a finding.'
  desc 'fix', 'To properly set the group owner of "/etc/passwd", run the command: 

# chgrp root /etc/passwd'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9070r357431_chk'
  tag severity: 'medium'
  tag gid: 'V-208817'
  tag rid: 'SV-208817r603263_rule'
  tag stig_id: 'OL6-00-000040'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9070r357432_fix'
  tag 'documentable'
  tag legacy: ['V-50771', 'SV-64977']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
