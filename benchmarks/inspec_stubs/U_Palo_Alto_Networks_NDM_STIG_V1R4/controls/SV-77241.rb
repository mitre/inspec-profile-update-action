control 'SV-77241' do
  title 'The Palo Alto Networks security platform must have alarms enabled.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability, and system operation may be adversely affected. 

Alerts provide organizations with urgent messages. Real-time alerts provide these messages immediately (i.e., the time from event detection to alert occurs in seconds or less).'
  desc 'check', 'Go to Device >> Log Settings >> Alarms
If the "Enable Alarms" box is not checked, this is a finding.'
  desc 'fix', 'Go to Device >> Log Settings >> Alarms
Select the "Edit" icon (the gear symbol in the upper-right corner of the pane).
In the "Alarm Settings" window; select the "Enable Alarms" box.
Select "OK".
Commit changes by selecting "Commit" in the upper-right corner of the screen.
Select "OK" when the confirmation dialog appears.'
  impact 0.3
  ref 'DPMS Target Palo Alto Networks Security Platform NDM'
  tag check_id: 'C-63559r1_chk'
  tag severity: 'low'
  tag gid: 'V-62751'
  tag rid: 'SV-77241r1_rule'
  tag stig_id: 'PANW-NM-000097'
  tag gtitle: 'SRG-APP-000360-NDM-000295'
  tag fix_id: 'F-68671r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
