control 'SV-77215' do
  title 'If multifactor authentication is not available and passwords must be used, the Palo Alto Networks security platform must prohibit password reuse for a minimum of five generations.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.  To meet password policy requirements, passwords need to be changed at specific policy-based intervals.

If the network device allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.'
  desc 'check', 'Go to Device >> Setup >> Management
View the "Minimum Password Complexity" window.
If the "Prevent Password Reuse Limit" field is not "5", this is a finding.'
  desc 'fix', 'Go to Device >> Setup >> Management
In the "Minimum Password Complexity" window, select the "Edit" icon (the gear symbol in the upper-right corner of the pane).
In the "Prevent Password Reuse Limit" field, enter "5".
Check the "Enabled" box, then select "OK".
Commit changes by selecting "Commit" in the upper-right corner of the screen.
Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks Security Platform NDM'
  tag check_id: 'C-63531r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62725'
  tag rid: 'SV-77215r1_rule'
  tag stig_id: 'PANW-NM-000054'
  tag gtitle: 'SRG-APP-000165-NDM-000253'
  tag fix_id: 'F-68645r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
