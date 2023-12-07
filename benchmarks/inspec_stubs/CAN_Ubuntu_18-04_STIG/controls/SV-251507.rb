control 'SV-251507' do
  title 'The Ubuntu operating system must not allow accounts configured with blank or null passwords.'
  desc 'If an account has an empty password, anyone could log on and run commands with the privileges of that account. Accounts with empty passwords should never be used in operational environments.'
  desc 'check', 'To verify that null passwords cannot be used, run the following command: 

$ grep nullok /etc/pam.d/common-password

If this produces any output, it may be possible to log on with accounts with empty passwords.

If null passwords can be used, this is a finding.'
  desc 'fix', 'If an account is configured for password authentication but does not have an assigned password, it may be possible to log on to the account without authenticating.

Remove any instances of the "nullok" option in "/etc/pam.d/common-password" to prevent logons with empty passwords.'
  impact 0.7
  ref 'DPMS Target Canonical Ubuntu 18.04 LTS'
  tag check_id: 'C-54942r832929_chk'
  tag severity: 'high'
  tag gid: 'V-251507'
  tag rid: 'SV-251507r832931_rule'
  tag stig_id: 'UBTU-18-010523'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-54896r832930_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
