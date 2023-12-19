control 'SV-220716' do
  title 'Accounts must be configured to require password expiration.'
  desc 'Passwords that do not expire increase exposure with a greater probability of being discovered or cracked.'
  desc 'check', 'Run "Computer Management".
Navigate to System Tools >> Local Users and Groups >> Users.
Double click each active account.

If "Password never expires" is selected for any account, this is a finding.'
  desc 'fix', 'Configure all passwords to expire.
Run "Computer Management".
Navigate to System Tools >> Local Users and Groups >> Users.
Double click each active account.
Ensure "Password never expires" is not checked on all active accounts.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22431r554633_chk'
  tag severity: 'medium'
  tag gid: 'V-220716'
  tag rid: 'SV-220716r569187_rule'
  tag stig_id: 'WN10-00-000090'
  tag gtitle: 'SRG-OS-000076-GPOS-00044'
  tag fix_id: 'F-22420r554634_fix'
  tag 'documentable'
  tag legacy: ['V-63371', 'SV-77861']
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
