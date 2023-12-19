control 'SV-208813' do
  title 'The /etc/gshadow file must be owned by root.'
  desc 'The "/etc/gshadow" file contains group password hashes. Protection of this file is critical for system security.'
  desc 'check', 'To check the ownership of "/etc/gshadow", run the command: 

$ ls -l /etc/gshadow

If properly configured, the output should indicate the following owner: "root" 
If it does not, this is a finding.'
  desc 'fix', 'To properly set the owner of "/etc/gshadow", run the command: 

# chown root /etc/gshadow'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9066r357419_chk'
  tag severity: 'medium'
  tag gid: 'V-208813'
  tag rid: 'SV-208813r793598_rule'
  tag stig_id: 'OL6-00-000036'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9066r357420_fix'
  tag 'documentable'
  tag legacy: ['V-50759', 'SV-64965']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
