control 'SV-221687' do
  title 'The Oracle Linux operating system must not allow accounts configured with blank or null passwords.'
  desc 'If an account has an empty password, anyone could log on and run commands with the privileges of that account. Accounts with empty passwords should never be used in operational environments.'
  desc 'check', 'To verify that null passwords cannot be used, run the following command: 

# grep nullok /etc/pam.d/system-auth /etc/pam.d/password-auth

If this produces any output, it may be possible to log on with accounts with empty passwords.

If null passwords can be used, this is a finding.'
  desc 'fix', 'If an account is configured for password authentication but does not have an assigned password, it may be possible to log on to the account without authenticating.

Remove any instances of the "nullok" option in "/etc/pam.d/system-auth" and "/etc/pam.d/password-auth" to prevent logons with empty passwords.

Note: Manual changes to the listed files may be overwritten by the "authconfig" program. The "authconfig" program should not be used to update the configurations listed in this requirement.'
  impact 0.7
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23402r419133_chk'
  tag severity: 'high'
  tag gid: 'V-221687'
  tag rid: 'SV-221687r809141_rule'
  tag stig_id: 'OL07-00-010290'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-23391r419134_fix'
  tag 'documentable'
  tag legacy: ['V-99113', 'SV-108217']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
