control 'SV-218226' do
  title 'The system must not have accounts configured with blank or null passwords.'
  desc 'If an account is configured for password authentication but does not have an assigned password, it may be possible to log into the account without authentication.  If the root user is configured without a password, the entire system may be compromised.  For user accounts not using password authentication, the account must be configured with a password lock value instead of a blank or null value.'
  desc 'check', 'Verify the system will not log in accounts with blank passwords.
# grep nullok /etc/pam.d/system-auth /etc/pam.d/system-auth-ac
If an entry for nullok is found, this is a finding on Linux.'
  desc 'fix', 'Edit /etc/pam.d/system-auth and remove the "nullok" setting.'
  impact 0.7
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19701r561416_chk'
  tag severity: 'high'
  tag gid: 'V-218226'
  tag rid: 'SV-218226r603259_rule'
  tag stig_id: 'GEN000560'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19699r561417_fix'
  tag 'documentable'
  tag legacy: ['V-770', 'SV-63787']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
