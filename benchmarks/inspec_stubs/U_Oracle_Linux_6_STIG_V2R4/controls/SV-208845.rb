control 'SV-208845' do
  title 'The system must not permit interactive boot.'
  desc 'Using interactive boot, the console user could disable auditing, firewalls, or other services, weakening system security.'
  desc 'check', 'To check whether interactive boot is disabled, run the following command: 

$ grep PROMPT /etc/sysconfig/init

If interactive boot is disabled, the output will show: 

PROMPT=no

If it does not, this is a finding.'
  desc 'fix', 'To disable the ability for users to perform interactive startups, edit the file "/etc/sysconfig/init". Add or correct the line: 

PROMPT=no

The "PROMPT" option allows the console user to perform an interactive system startup, in which it is possible to select the set of services which are started on boot.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9098r357515_chk'
  tag severity: 'medium'
  tag gid: 'V-208845'
  tag rid: 'SV-208845r603263_rule'
  tag stig_id: 'OL6-00-000070'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-9098r357516_fix'
  tag 'documentable'
  tag legacy: ['V-50951', 'SV-65157']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
