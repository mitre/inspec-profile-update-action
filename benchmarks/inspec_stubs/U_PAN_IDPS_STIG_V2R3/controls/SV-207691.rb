control 'SV-207691' do
  title 'In the event of a logging failure caused by the lack of audit record storage capacity, the Palo Alto Networks security platform must continue generating and storing audit records if possible, overwriting the oldest audit records in a first-in-first-out manner.'
  desc 'It is critical that when the Palo Alto Networks security platform is at risk of failing to process audit logs as required, it takes action to mitigate the failure.

The Palo Alto Networks security platform performs a critical security function, so its continued operation is imperative. Since availability of the Palo Alto Networks security platform is an overriding concern, shutting down the system in the event of an audit failure should be avoided, except as a last resort.'
  desc 'check', 'Note: overwriting the oldest audit records in a first-in-first-out manner is the default setting of the Palo Alto Networks security platform.
 
Go to Device >> Setup
In the "Logging and Reporting Settings" pane, if the "Stop Traffic when LogDb Full" checkbox is selected, this is a finding.'
  desc 'fix', 'Note: Overwriting the oldest audit records in a first-in-first-out manner is the default setting of the Palo Alto Networks security platform.
  
Go to Device >> Setup
In the "Logging and Reporting Settings" pane, select the "Edit" icon in the upper-right corner.
In the "Logging and Reporting Settings" window, in the "Log Export and Reporting" tab, deselect (uncheck) the "Stop Traffic when LogDb Full" checkbox.  If it is already not selected, do not change it.
Switch back to the "Log Storage" tab.
Select "OK".

If no changes were made, it is not necessary or possible to commit a change.  If a change was made, commit changes by selecting "Commit" in the upper-right corner of the screen.  Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks IDPS'
  tag check_id: 'C-7945r358406_chk'
  tag severity: 'medium'
  tag gid: 'V-207691'
  tag rid: 'SV-207691r557390_rule'
  tag stig_id: 'PANW-IP-000010'
  tag gtitle: 'SRG-NET-000089-IDPS-00069'
  tag fix_id: 'F-7945r358407_fix'
  tag 'documentable'
  tag legacy: ['SV-77143', 'V-62653']
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end
