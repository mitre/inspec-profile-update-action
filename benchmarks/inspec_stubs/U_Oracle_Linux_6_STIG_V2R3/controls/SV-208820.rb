control 'SV-208820' do
  title 'The /etc/group file must be group-owned by root.'
  desc 'The "/etc/group" file contains information regarding groups that are configured on the system. Protection of this file is important for system security.'
  desc 'check', 'To check the group ownership of "/etc/group", run the command: 

$ ls -l /etc/group

If properly configured, the output should indicate the following group-owner. "root" 
If it does not, this is a finding.'
  desc 'fix', 'To properly set the group owner of "/etc/group", run the command: 

# chgrp root /etc/group'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9073r357440_chk'
  tag severity: 'medium'
  tag gid: 'V-208820'
  tag rid: 'SV-208820r603263_rule'
  tag stig_id: 'OL6-00-000043'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9073r357441_fix'
  tag 'documentable'
  tag legacy: ['SV-64983', 'V-50777']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
