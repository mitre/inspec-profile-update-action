control 'SV-208807' do
  title 'The system must not allow accounts configured with blank or null passwords.'
  desc 'If an account has an empty password, anyone could log in and run commands with the privileges of that account. Accounts with empty passwords should never be used in operational environments.'
  desc 'check', 'To verify that null passwords cannot be used, run the following command:

# grep nullok /etc/pam.d/system-auth /etc/pam.d/password-auth

If this produces any output, it may be possible to log on to accounts with empty passwords.

If null passwords can be used, this is a finding.'
  desc 'fix', 'If an account is configured for password authentication but does not have an assigned password, it may be possible to log on to the account without authentication.

Remove any instances of the "nullok" option in "/etc/pam.d/system-auth" and "/etc/pam.d/password-auth" to prevent logons with empty passwords.'
  impact 0.7
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9060r357401_chk'
  tag severity: 'high'
  tag gid: 'V-208807'
  tag rid: 'SV-208807r809110_rule'
  tag stig_id: 'OL6-00-000030'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9060r357402_fix'
  tag 'documentable'
  tag legacy: ['V-50737', 'SV-64943']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
