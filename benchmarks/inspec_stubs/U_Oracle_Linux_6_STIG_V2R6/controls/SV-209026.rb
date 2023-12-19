control 'SV-209026' do
  title 'All accounts on the system must have unique user or account names.'
  desc 'Unique usernames allow for accountability on the system.'
  desc 'check', 'Run the following command to check for duplicate account names: 

# pwck -rq

If there are no duplicate names, no line will be returned. 
If a line is returned, this is a finding.'
  desc 'fix', 'Change usernames, or delete accounts, so each has a unique name.'
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9279r357863_chk'
  tag severity: 'low'
  tag gid: 'V-209026'
  tag rid: 'SV-209026r793747_rule'
  tag stig_id: 'OL6-00-000296'
  tag gtitle: 'SRG-OS-000121'
  tag fix_id: 'F-9279r357864_fix'
  tag 'documentable'
  tag legacy: ['SV-65191', 'V-50985']
  tag cci: ['CCI-000804']
  tag nist: ['IA-8']
end
