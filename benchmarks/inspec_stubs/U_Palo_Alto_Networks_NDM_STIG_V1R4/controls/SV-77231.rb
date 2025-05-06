control 'SV-77231' do
  title 'The Palo Alto Networks security platform must enforce a 60-day maximum password lifetime restriction.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed at specific intervals.

One method of minimizing this risk is to use complex passwords and periodically change them. If the network device does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the passwords could be compromised.

This requirement does not include emergency administration accounts that are meant for access to the network device in case of failure. These accounts are not required to have maximum password lifetime restrictions.'
  desc 'check', 'Go to Device >> Setup >> Management
View the "Minimum Password Complexity" window.
If the "Required Password Change Period (days)" field is not "60", this is a finding.'
  desc 'fix', 'Go to Device >> Setup >> Management
In the "Minimum Password Complexity" window, select the "Edit" icon (the gear symbol in the upper-right corner of the pane).
In the "Required Password Change Period (days)" field, enter "60".
Check the "Enabled box", then select "OK".
Commit changes by selecting "Commit" in the upper-right corner of the screen.
Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks Security Platform NDM'
  tag check_id: 'C-63549r2_chk'
  tag severity: 'medium'
  tag gid: 'V-62741'
  tag rid: 'SV-77231r1_rule'
  tag stig_id: 'PANW-NM-000063'
  tag gtitle: 'SRG-APP-000174-NDM-000261'
  tag fix_id: 'F-68661r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
