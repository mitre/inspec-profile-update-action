control 'SV-77213' do
  title 'If multifactor authentication is not available and passwords must be used, the Palo Alto Networks security platform must enforce a minimum 15-character password length.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password.

The shorter the password, the lower the number of possible combinations that needs to be tested before the password is compromised. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'Go to Device >> Setup >> Management
View the "Minimum Password Complexity" window.
If the "Minimum Length" field is not "15", this is a finding.'
  desc 'fix', 'Go to Device >> Setup >> Management 
In the "Minimum Password Complexity" window, select the "Edit" icon (the gear symbol in the upper-right corner of the pane).
In the "Minimum Length" field, enter "15".
Check the "Enabled" box, then select "OK".
Commit changes by selecting "Commit" in the upper-right corner of the screen.
Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks Security Platform NDM'
  tag check_id: 'C-63529r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62723'
  tag rid: 'SV-77213r1_rule'
  tag stig_id: 'PANW-NM-000053'
  tag gtitle: 'SRG-APP-000164-NDM-000252'
  tag fix_id: 'F-68643r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
