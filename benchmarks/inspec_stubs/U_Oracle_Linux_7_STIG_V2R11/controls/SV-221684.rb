control 'SV-221684' do
  title 'The Oracle Linux operating system must be configured so that existing passwords are restricted to a 60-day maximum lifetime.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed periodically. If the operating system does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the operating system passwords could be compromised.'
  desc 'check', %q(Check whether the maximum time period for existing passwords is restricted to 60 days.

# awk -F: '$5 > 60 {print $1 " " $5}' /etc/shadow

If any results are returned that are not associated with a system account, this is a finding.)
  desc 'fix', 'Configure non-compliant accounts to enforce a 60-day maximum password lifetime restriction.

# chage -M 60 [user]'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23399r419124_chk'
  tag severity: 'medium'
  tag gid: 'V-221684'
  tag rid: 'SV-221684r603260_rule'
  tag stig_id: 'OL07-00-010260'
  tag gtitle: 'SRG-OS-000076-GPOS-00044'
  tag fix_id: 'F-23388r419125_fix'
  tag 'documentable'
  tag legacy: ['V-99107', 'SV-108211']
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
