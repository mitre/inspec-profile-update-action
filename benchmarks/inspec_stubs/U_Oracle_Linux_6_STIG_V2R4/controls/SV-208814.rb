control 'SV-208814' do
  title 'The /etc/gshadow file must be group-owned by root.'
  desc 'The "/etc/gshadow" file contains group password hashes. Protection of this file is critical for system security.'
  desc 'check', 'To check the group ownership of "/etc/gshadow", run the command: 

$ ls -l /etc/gshadow

If properly configured, the output should indicate the following group-owner. "root" 
If it does not, this is a finding.'
  desc 'fix', 'To properly set the group owner of "/etc/gshadow", run the command: 

# chgrp root /etc/gshadow'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9067r357422_chk'
  tag severity: 'medium'
  tag gid: 'V-208814'
  tag rid: 'SV-208814r603263_rule'
  tag stig_id: 'OL6-00-000037'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9067r357423_fix'
  tag 'documentable'
  tag legacy: ['V-50763', 'SV-64969']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
