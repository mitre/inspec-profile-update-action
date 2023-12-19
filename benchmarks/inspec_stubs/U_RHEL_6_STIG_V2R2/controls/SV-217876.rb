control 'SV-217876' do
  title 'The /etc/gshadow file must have mode 0000.'
  desc 'The /etc/gshadow file contains group password hashes. Protection of this file is critical for system security.'
  desc 'check', 'To check the permissions of "/etc/gshadow", run the command: 

$ ls -l /etc/gshadow

If properly configured, the output should indicate the following permissions: "----------" 
If it does not, this is a finding.'
  desc 'fix', 'To properly set the permissions of "/etc/gshadow", run the command: 

# chmod 0000 /etc/gshadow'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19357r376643_chk'
  tag severity: 'medium'
  tag gid: 'V-217876'
  tag rid: 'SV-217876r603264_rule'
  tag stig_id: 'RHEL-06-000038'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-19355r376644_fix'
  tag 'documentable'
  tag legacy: ['V-38449', 'SV-50249']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
