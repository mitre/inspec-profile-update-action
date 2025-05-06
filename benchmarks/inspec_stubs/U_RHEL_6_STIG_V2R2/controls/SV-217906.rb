control 'SV-217906' do
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
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19387r376733_chk'
  tag severity: 'medium'
  tag gid: 'V-217906'
  tag rid: 'SV-217906r603264_rule'
  tag stig_id: 'RHEL-06-000070'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-19385r376734_fix'
  tag 'documentable'
  tag legacy: ['V-38588', 'SV-50389']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
