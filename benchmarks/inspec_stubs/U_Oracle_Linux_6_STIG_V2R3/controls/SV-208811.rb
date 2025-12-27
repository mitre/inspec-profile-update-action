control 'SV-208811' do
  title 'The /etc/shadow file must be group-owned by root.'
  desc 'The "/etc/shadow" file stores password hashes. Protection of this file is critical for system security.'
  desc 'check', 'To check the group ownership of "/etc/shadow", run the command: 

$ ls -l /etc/shadow

If properly configured, the output should indicate the following group-owner. "root" 
If it does not, this is a finding.'
  desc 'fix', 'To properly set the group owner of "/etc/shadow", run the command: 

# chgrp root /etc/shadow'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9064r357413_chk'
  tag severity: 'medium'
  tag gid: 'V-208811'
  tag rid: 'SV-208811r603263_rule'
  tag stig_id: 'OL6-00-000034'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9064r357414_fix'
  tag 'documentable'
  tag legacy: ['V-50755', 'SV-64961']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
