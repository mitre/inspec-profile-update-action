control 'SV-228652' do
  title 'If multifactor authentication is not available and passwords must be used, the Palo Alto Networks security platform must enforce password complexity by requiring that at least one numeric character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that needs to be tested before the password is compromised.'
  desc 'check', 'Go to Device >> Setup >> Management
View the "Minimum Password Complexity" window.
If the "Minimum Numeric Letters" field is not "1", this is a finding.'
  desc 'fix', 'Go to Device >> Setup >> Management
In the "Minimum Password Complexity" window, select the "Edit" icon (the gear symbol in the upper-right corner of the pane).
In the "Minimum Numeric Letters" field, enter "1".
Check the "Enabled" box, then select "OK".
Commit changes by selecting "Commit" in the upper-right corner of the screen.
Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks NDM'
  tag check_id: 'C-30887r513559_chk'
  tag severity: 'medium'
  tag gid: 'V-228652'
  tag rid: 'SV-228652r513561_rule'
  tag stig_id: 'PANW-NM-000057'
  tag gtitle: 'SRG-APP-000168-NDM-000256'
  tag fix_id: 'F-30864r513560_fix'
  tag 'documentable'
  tag legacy: ['SV-77221', 'V-62731']
  tag cci: ['CCI-000194']
  tag nist: ['IA-5 (1) (a)']
end
