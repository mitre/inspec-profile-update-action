control 'SV-204421' do
  title 'The Red Hat Enterprise Linux operating system must be configured so that existing passwords are restricted to a 60-day maximum lifetime.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed periodically. If the operating system does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the operating system passwords could be compromised.'
  desc 'check', %q(Check whether the maximum time period for existing passwords is restricted to 60 days.

# awk -F: '$5 > 60 {print $1 " " $5}' /etc/shadow

If any results are returned that are not associated with a system account, this is a finding.)
  desc 'fix', 'Configure non-compliant accounts to enforce a 60-day maximum password lifetime restriction.

# chage -M 60 [user]'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 7'
  tag check_id: 'C-4545r88455_chk'
  tag severity: 'medium'
  tag gid: 'V-204421'
  tag rid: 'SV-204421r603261_rule'
  tag stig_id: 'RHEL-07-010260'
  tag gtitle: 'SRG-OS-000076-GPOS-00044'
  tag fix_id: 'F-4545r88456_fix'
  tag 'documentable'
  tag legacy: ['V-71931', 'SV-86555']
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
