control 'SV-248696' do
  title 'OL 8 user account passwords must have a 60-day maximum password lifetime restriction.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed periodically. If OL 8 does not limit the lifetime of passwords and force users to change their passwords, there is the risk that OL 8 passwords could be compromised.'
  desc 'check', 'Verify that OL 8 enforces a 60-day maximum password lifetime for new user accounts by running the following command:

$ sudo grep -i pass_max_days /etc/login.defs
PASS_MAX_DAYS 60

If the "PASS_MAX_DAYS" parameter value is greater than "60", or commented out, this is a finding.'
  desc 'fix', 'Configure OL 8 to enforce a 60-day maximum password lifetime. 
 
Add or modify the following line in the "/etc/login.defs" file: 
 
PASS_MAX_DAYS 60'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52130r779652_chk'
  tag severity: 'medium'
  tag gid: 'V-248696'
  tag rid: 'SV-248696r779654_rule'
  tag stig_id: 'OL08-00-020200'
  tag gtitle: 'SRG-OS-000076-GPOS-00044'
  tag fix_id: 'F-52084r779653_fix'
  tag 'documentable'
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
