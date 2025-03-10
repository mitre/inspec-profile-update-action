control 'SV-217878' do
  title 'The /etc/passwd file must be group-owned by root.'
  desc 'The "/etc/passwd" file contains information about the users that are configured on the system. Protection of this file is critical for system security.'
  desc 'check', 'To check the group ownership of "/etc/passwd", run the command: 

$ ls -l /etc/passwd

If properly configured, the output should indicate the following group-owner. "root" 
If it does not, this is a finding.'
  desc 'fix', 'To properly set the group owner of "/etc/passwd", run the command: 

# chgrp root /etc/passwd'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19359r376649_chk'
  tag severity: 'medium'
  tag gid: 'V-217878'
  tag rid: 'SV-217878r603264_rule'
  tag stig_id: 'RHEL-06-000040'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-19357r376650_fix'
  tag 'documentable'
  tag legacy: ['V-38451', 'SV-50251']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
