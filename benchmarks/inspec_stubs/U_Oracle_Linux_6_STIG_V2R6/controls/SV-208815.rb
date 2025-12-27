control 'SV-208815' do
  title 'The /etc/gshadow file must have mode 0000.'
  desc 'The /etc/gshadow file contains group password hashes. Protection of this file is critical for system security.'
  desc 'check', 'To check the permissions of "/etc/gshadow", run the command: 

$ ls -l /etc/gshadow

If properly configured, the output should indicate the following permissions: "----------" 
If it does not, this is a finding.'
  desc 'fix', 'To properly set the permissions of "/etc/gshadow", run the command: 

# chmod 0000 /etc/gshadow'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9068r357425_chk'
  tag severity: 'medium'
  tag gid: 'V-208815'
  tag rid: 'SV-208815r793600_rule'
  tag stig_id: 'OL6-00-000038'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9068r357426_fix'
  tag 'documentable'
  tag legacy: ['V-50765', 'SV-64971']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
