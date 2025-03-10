control 'SV-228654' do
  title 'If multifactor authentication is not available and passwords must be used, the Palo Alto Networks security platform must require that when a password is changed, the characters are changed in at least 8 of the positions within the password.'
  desc 'If the application allows the user to consecutively reuse extensive portions of passwords, this increases the chances of password compromise by increasing the window of opportunity for attempts at guessing and brute-force attacks.

The number of changed characters refers to the number of changes required with respect to the total number of positions in the current password. In other words, characters may be the same within the two passwords; however, the positions of the like characters must be different.'
  desc 'check', 'Go to Device >> Setup >> Management
View the "Minimum Password Complexity" window.
If the "New Password Differs by Characters" field is not "8", this is a finding.'
  desc 'fix', 'Go to Device >> Setup >> Management
In the "Minimum Password Complexity" window, select the "Edit" icon (the gear symbol in the upper-right corner of the pane).
In the "New Password Differs by Characters" field, enter "8".
Check the "Enabled box", then select "OK".
Commit changes by selecting "Commit" in the upper-right corner of the screen.
Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks NDM'
  tag check_id: 'C-30889r513565_chk'
  tag severity: 'medium'
  tag gid: 'V-228654'
  tag rid: 'SV-228654r513567_rule'
  tag stig_id: 'PANW-NM-000059'
  tag gtitle: 'SRG-APP-000170-NDM-000329'
  tag fix_id: 'F-30866r513566_fix'
  tag 'documentable'
  tag legacy: ['SV-77225', 'V-62735']
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']
end
