control 'SV-230968' do
  title 'Forescout must require that when a password is changed, the characters are changed in at least eight of the positions within the password.'
  desc 'If the application allows the user to consecutively reuse extensive portions of passwords, this increases the chances of password compromise by increasing the window of opportunity for attempts at guessing and brute-force attacks.

The number of changed characters refers to the number of changes required with respect to the total number of positions in the current password. In other words, characters may be the same within the two passwords; however, the positions of the like characters must be different.

Multifactor authentication (MFA) is required for all administrative and user accounts on network devices, except for an account of last resort and (where applicable) a root account. Passwords should only be used when MFA using PKI is not available, and for the account of last resort and root account.'
  desc 'check', '1. From the menu, select Tools >> Options >> CounterACT User Profiles >> Password and Sessions.
2. Verify the fifth "password must contain at least" is checked. 
3. Verify there is 1 (or higher) in the "repeated characters or digits" configuration box.

If Forescout does not enforce the requirement that when the password is changed, the characters are changed in at least eight of the positions within the password, this is a finding.'
  desc 'fix', 'Configure Forescout to be required that when a password is changed, the characters are changed in at least eight of the positions within the password.

1. From the menu, select Tools >> Options >> CounterACT User Profiles >> Password and Sessions.
2. Check the fifth "password must contain at least" option.
3. Add a 1 (or higher) in the "repeated characters or digits" configuration box.'
  impact 0.3
  ref 'DPMS Target Forescout Network Device Management'
  tag check_id: 'C-33898r603743_chk'
  tag severity: 'low'
  tag gid: 'V-230968'
  tag rid: 'SV-230968r615886_rule'
  tag stig_id: 'FORE-NM-000420'
  tag gtitle: 'SRG-APP-000170-NDM-000329'
  tag fix_id: 'F-33871r603744_fix'
  tag 'documentable'
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']
end
