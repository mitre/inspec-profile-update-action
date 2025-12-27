control 'SV-215197' do
  title 'AIX must not have accounts configured with blank or null passwords.'
  desc 'If an account is configured for password authentication but does not have an assigned password, it may be possible to log into the account without authentication. If the root user is configured without a password, the entire system may be compromised. For user accounts not using password authentication, the account must be configured with a password lock value instead of a blank or null value.'
  desc 'check', 'Verify no interactive accounts have blank passwords by running the following command: 
# pwdck -n ALL 

If any interactive account with a blank password is found, this is a finding.'
  desc 'fix', 'Configure a password for any interactive account with a blank password by running the following command:
# passwd [user_name]'
  impact 0.7
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16395r294042_chk'
  tag severity: 'high'
  tag gid: 'V-215197'
  tag rid: 'SV-215197r508663_rule'
  tag stig_id: 'AIX7-00-001038'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag fix_id: 'F-16393r294043_fix'
  tag 'documentable'
  tag legacy: ['V-91737', 'SV-101835']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
