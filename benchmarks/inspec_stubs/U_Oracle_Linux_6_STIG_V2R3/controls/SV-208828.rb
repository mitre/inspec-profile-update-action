control 'SV-208828' do
  title 'User passwords must be changed at least every 60 days.'
  desc 'Setting the password maximum age ensures users are required to periodically change their passwords. This could possibly decrease the utility of a stolen password. Requiring shorter password lifetimes increases the risk of users writing down the password in a convenient location subject to physical compromise.'
  desc 'check', 'To check the maximum password age, run the command: 

$ grep PASS_MAX_DAYS /etc/login.defs

The DoD requirement is 60. 
If it is not set to the required value, this is a finding.'
  desc 'fix', 'To specify password maximum age for new accounts, edit the file "/etc/login.defs" and add or correct the following line, replacing [DAYS] appropriately: 

PASS_MAX_DAYS [DAYS]

The DoD requirement is 60.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9081r357464_chk'
  tag severity: 'medium'
  tag gid: 'V-208828'
  tag rid: 'SV-208828r603263_rule'
  tag stig_id: 'OL6-00-000053'
  tag gtitle: 'SRG-OS-000076'
  tag fix_id: 'F-9081r357465_fix'
  tag 'documentable'
  tag legacy: ['SV-65001', 'V-50795']
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
