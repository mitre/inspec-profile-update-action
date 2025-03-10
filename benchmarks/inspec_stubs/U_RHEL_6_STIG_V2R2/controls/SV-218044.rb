control 'SV-218044' do
  title 'All accounts on the system must have unique user or account names'
  desc 'Unique usernames allow for accountability on the system.'
  desc 'check', 'Run the following command to check for duplicate account names: 

# pwck -rq

If there are no duplicate names, no line will be returned. 
If a line is returned, this is a finding.'
  desc 'fix', 'Change usernames, or delete accounts, so each has a unique name.'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19525r377147_chk'
  tag severity: 'low'
  tag gid: 'V-218044'
  tag rid: 'SV-218044r603264_rule'
  tag stig_id: 'RHEL-06-000296'
  tag gtitle: 'SRG-OS-000121'
  tag fix_id: 'F-19523r377148_fix'
  tag 'documentable'
  tag legacy: ['V-38683', 'SV-50484']
  tag cci: ['CCI-000804']
  tag nist: ['IA-8']
end
