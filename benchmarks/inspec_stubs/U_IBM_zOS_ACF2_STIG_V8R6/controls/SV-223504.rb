control 'SV-223504' do
  title 'ACF2 PSWD GSO record value must be set to require the change of at least 50% of the total number of characters when passwords are changed.'
  desc 'If the operating system allows the user to consecutively reuse extensive portions of passwords, this increases the chances of password compromise by increasing the window of opportunity for attempts at guessing and brute-force attacks.

The number of changed characters refers to the number of changes required with respect to the total number of positions in the current password. In other words, characters may be the same within the two passwords; however, the positions of the like characters must be different.

If the password length is an odd number then number of changed characters must be rounded up. For example, a password length of 15 characters must require the change of at least 8 characters.'
  desc 'check', 'From an ACF command screen enter:
SET CONTROL(GSO)
LIST PSWD

If "PSWDSIM" is set to "4", this is not a finding.'
  desc 'fix', 'Configure the Password option "PSWDSIM" to "4".'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25177r695432_chk'
  tag severity: 'medium'
  tag gid: 'V-223504'
  tag rid: 'SV-223504r695433_rule'
  tag stig_id: 'ACF2-ES-000870'
  tag gtitle: 'SRG-OS-000072-GPOS-00040'
  tag fix_id: 'F-25165r500646_fix'
  tag 'documentable'
  tag legacy: ['SV-106813', 'V-97709']
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']
end
