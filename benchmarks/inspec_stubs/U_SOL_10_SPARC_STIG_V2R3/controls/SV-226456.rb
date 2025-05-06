control 'SV-226456' do
  title 'The system must not have accounts configured with blank or null passwords.'
  desc 'If an account is configured for password authentication but does not have an assigned password, it may be possible to log into the account without authentication.  If the root user is configured without a password, the entire system may be compromised.  For user accounts not using password authentication, the account must be configured with a password lock value instead of a blank or null value.'
  desc 'check', 'Verify no accounts have blank passwords.

# logins -p

If any account with a blank password is found, this is a finding.'
  desc 'fix', 'Remove, lock, or configure a password for any account with a blank password.'
  impact 0.7
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28617r482744_chk'
  tag severity: 'high'
  tag gid: 'V-226456'
  tag rid: 'SV-226456r603265_rule'
  tag stig_id: 'GEN000560'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28605r482745_fix'
  tag 'documentable'
  tag legacy: ['SV-27105', 'V-770']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
