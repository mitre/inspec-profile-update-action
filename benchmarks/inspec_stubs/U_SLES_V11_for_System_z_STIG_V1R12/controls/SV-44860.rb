control 'SV-44860' do
  title 'The system must not have accounts configured with blank or null passwords.'
  desc 'If an account is configured for password authentication but does not have an assigned password, it may be possible to log into the account without authentication.  If the root user is configured without a password, the entire system may be compromised.  For user accounts not using password authentication, the account must be configured with a password lock value instead of a blank or null value.'
  desc 'check', 'Verify the system will not log in accounts with blank passwords.
# grep nullok /etc/pam.d/common-auth
# grep nullok /etc/pam.d/common-account
# grep nullok /etc/pam.d/common-password
# grep nullok /etc/pam.d/common-session
If an entry for nullok is found, this is a finding on Linux.'
  desc 'fix', 'Edit /etc/pam.d/<configuration file> and remove the "nullok" setting.

OR

Use ‘pam-config’ to configure the affected module if it is supported by pam-config'
  impact 0.7
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42322r1_chk'
  tag severity: 'high'
  tag gid: 'V-770'
  tag rid: 'SV-44860r1_rule'
  tag stig_id: 'GEN000560'
  tag gtitle: 'GEN000560'
  tag fix_id: 'F-38293r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
