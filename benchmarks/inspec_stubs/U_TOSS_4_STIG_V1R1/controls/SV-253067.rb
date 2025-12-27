control 'SV-253067' do
  title 'TOSS must enforce a 60-day maximum password lifetime restriction.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed periodically. If the operating system does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the operating system passwords could be compromised.'
  desc 'check', 'Verify that TOSS enforces a 60-day maximum password lifetime for new user accounts by running the following command:

$ sudo grep -i pass_max_days /etc/login.defs
PASS_MAX_DAYS 60

If the "PASS_MAX_DAYS" parameter value is greater than "60", or commented out, this is a finding.'
  desc 'fix', 'Configure TOSS to enforce a 60-day maximum password lifetime.

Add, or modify the following line in the "/etc/login.defs" file:

PASS_MAX_DAYS 60'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56520r824871_chk'
  tag severity: 'medium'
  tag gid: 'V-253067'
  tag rid: 'SV-253067r824873_rule'
  tag stig_id: 'TOSS-04-040120'
  tag gtitle: 'SRG-OS-000076-GPOS-00044'
  tag fix_id: 'F-56470r824872_fix'
  tag 'documentable'
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
