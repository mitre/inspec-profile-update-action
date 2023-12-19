control 'SV-77229' do
  title 'The Palo Alto Networks security platform must enforce 24 hours/1 day as the minimum password lifetime.'
  desc "Enforcing a minimum password lifetime helps prevent repeated password changes to defeat the password reuse or history enforcement requirement.

Restricting this setting limits the user's ability to change their password. Passwords need to be changed at specific policy-based intervals; however, if the network device allows the user to immediately and continually change their password, then the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding password reuse."
  desc 'check', 'Go to Device >> Setup >> Management
View the "Minimum Password Complexity" window.
If the "Block Password Change Period (days)" field is not "1", this is a finding.'
  desc 'fix', 'Go to Device >> Setup >> Management
In the "Minimum Password Complexity" window, select the "Edit" icon (the gear symbol in the upper-right corner of the pane).
In the "Block Password Change Period (days)" field, enter "1".
Check the "Enabled box", then select "OK".
Commit changes by selecting "Commit" in the upper-right corner of the screen.
Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks Security Platform NDM'
  tag check_id: 'C-63545r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62739'
  tag rid: 'SV-77229r1_rule'
  tag stig_id: 'PANW-NM-000062'
  tag gtitle: 'SRG-APP-000173-NDM-000260'
  tag fix_id: 'F-68659r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000198']
  tag nist: ['IA-5 (1) (d)']
end
