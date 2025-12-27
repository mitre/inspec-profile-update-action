control 'SV-253909' do
  title 'The Juniper EX switch must be configured to require that when a password is changed, the characters are changed in at least eight of the positions within the password.'
  desc 'If the application allows the user to consecutively reuse extensive portions of passwords, this increases the chances of password compromise by increasing the window of opportunity for attempts at guessing and brute-force attacks.

The number of changed characters refers to the number of changes required with respect to the total number of positions in the current password. In other words, characters may be the same within the two passwords; however, the positions of the like characters must be different.

Multifactor authentication (MFA) is required for all administrative and user accounts on network devices, except for an account of last resort and (where applicable) a root account. Passwords should only be used when MFA using PKI is not available, and for the account of last resort and root account.'
  desc 'check', 'Where passwords are used, confirm the characters are changed in at least eight of the positions within the password. This requirement may be verified by demonstration, configuration review, or validated test results.

[edit system login password]
:
minimum-changes 8;
:

If the network device and associated authentication server does not require that when a password is changed, the characters are changed in at least eight of the positions within the password, this is a finding.'
  desc 'fix', 'Configure the network device and associated authentication server to require that when a password is changed, the characters are changed in at least eight of the positions within the password.

set system login password minimum-changes 8'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches NDM'
  tag check_id: 'C-57361r843758_chk'
  tag severity: 'medium'
  tag gid: 'V-253909'
  tag rid: 'SV-253909r843760_rule'
  tag stig_id: 'JUEX-NM-000320'
  tag gtitle: 'SRG-APP-000170-NDM-000329'
  tag fix_id: 'F-57312r843759_fix'
  tag 'documentable'
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']
end
