control 'SV-217868' do
  title 'The system must not have accounts configured with blank or null passwords.'
  desc 'If an account has an empty password, anyone could log in and run commands with the privileges of that account. Accounts with empty passwords should never be used in operational environments.'
  desc 'check', 'To verify that null passwords cannot be used, run the following command: 

# grep nullok /etc/pam.d/system-auth /etc/pam.d/password-auth

If this produces any output, it may be possible to log into accounts with empty passwords. 
If NULL passwords can be used, this is a finding.'
  desc 'fix', 'If an account is configured for password authentication but does not have an assigned password, it may be possible to log onto the account without authentication. Remove any instances of the "nullok" option in "/etc/pam.d/system-auth" and "/etc/pam.d/password-auth" to prevent logons with empty passwords.'
  impact 0.7
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19349r376619_chk'
  tag severity: 'high'
  tag gid: 'V-217868'
  tag rid: 'SV-217868r603264_rule'
  tag stig_id: 'RHEL-06-000030'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-19347r376620_fix'
  tag 'documentable'
  tag legacy: ['V-38497', 'SV-50298']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
