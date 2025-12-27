control 'SV-217890' do
  title 'Users must be warned 7 days in advance of password expiration.'
  desc 'Setting the password warning age enables users to make the change at a practical time.'
  desc 'check', 'To check the password warning age, run the command: 

$ grep PASS_WARN_AGE /etc/login.defs

The DoD requirement is 7. 
If it is not set to the required value, this is a finding.'
  desc 'fix', 'To specify how many days prior to password expiration that a warning will be issued to users, edit the file "/etc/login.defs" and add or correct the following line, replacing [DAYS] appropriately: 

PASS_WARN_AGE [DAYS]

The DoD requirement is 7.'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19371r376685_chk'
  tag severity: 'low'
  tag gid: 'V-217890'
  tag rid: 'SV-217890r603264_rule'
  tag stig_id: 'RHEL-06-000054'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-19369r376686_fix'
  tag 'documentable'
  tag legacy: ['V-38480', 'SV-50280']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
