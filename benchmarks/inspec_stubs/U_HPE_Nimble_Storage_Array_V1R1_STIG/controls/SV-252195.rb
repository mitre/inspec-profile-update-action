control 'SV-252195' do
  title 'The HPE Nimble must require that when a password is changed, the characters are changed in at least eight of the positions within the password.'
  desc 'If the application allows the user to consecutively reuse extensive portions of passwords, this increases the chances of password compromise by increasing the window of opportunity for attempts at guessing and brute-force attacks.

The number of changed characters refers to the number of changes required with respect to the total number of positions in the current password. In other words, characters may be the same within the two passwords; however, the positions of the like characters must be different.

Multifactor authentication (MFA) is required for all administrative and user accounts on network devices, except for an account of last resort and (where applicable) a root account. Passwords should only be used when MFA using PKI is not available, and for the account of last resort and root account.'
  desc 'check', 'Type "userpolicy --info" and review output for line: "Minimum number of characters change from previous password". If it is 8 or more, this is not a finding.'
  desc 'fix', 'Set minimum number of characters changed from previous password to 8 by typing "userpolicy --edit --previous_diff 8".'
  impact 0.5
  ref 'DPMS Target HPE Nimble Storage Array'
  tag check_id: 'C-55651r814063_chk'
  tag severity: 'medium'
  tag gid: 'V-252195'
  tag rid: 'SV-252195r814065_rule'
  tag stig_id: 'HPEN-NM-000100'
  tag gtitle: 'SRG-APP-000170-NDM-000329'
  tag fix_id: 'F-55601r814064_fix'
  tag 'documentable'
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']
end
