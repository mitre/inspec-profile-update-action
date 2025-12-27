control 'SV-205500' do
  title 'The Mainframe Product must require the change of at least 8 of the total number of characters when passwords are changed.'
  desc 'If the application allows the user to consecutively reuse extensive portions of passwords, this increases the chances of password compromise by increasing the window of opportunity for attempts at guessing and brute-force attacks.

The number of changed characters refers to the number of changes required with respect to the total number of positions in the current password. In other words, characters may be the same within the two passwords; however, the positions of the like characters must be different.'
  desc 'check', 'If the Mainframe Product employs an external security manager (ESM) for all account management functions, this is not applicable.

Examine user account management configurations. 

If the Mainframe Product account management settings do  not require the change of at least 8 of the total  characters when passwords are changed, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product account management settings to require the change of at least 8 of the total characters when passwords are changed.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5766r299733_chk'
  tag severity: 'medium'
  tag gid: 'V-205500'
  tag rid: 'SV-205500r397519_rule'
  tag stig_id: 'SRG-APP-000170-MFP-000232'
  tag gtitle: 'SRG-APP-000170'
  tag fix_id: 'F-5766r299734_fix'
  tag 'documentable'
  tag legacy: ['SV-82873', 'V-68383']
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']
end
