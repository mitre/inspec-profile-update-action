control 'SV-77239' do
  title 'The Palo Alto Networks security platform must generate an immediate alert when allocated audit record storage volume reaches 75% of repository maximum audit record storage capacity.'
  desc 'If security personnel are not notified immediately upon storage volume utilization reaching 75%, they are unable to plan for storage capacity expansion. This could lead to the loss of audit information. Note that while the network device must generate the alert, notification may be done by a management server.'
  desc 'check', 'Go to Device >> Log Settings >> Alarms
If the Traffic Log DB, Threat Log DB, Configuration Log DB, System Log DB, Alarm DB, and HIP Match Log DB fields are not "75", this is a finding.'
  desc 'fix', 'Go to Device >> Log Settings >> Alarms
Select the "Edit" icon (the gear symbol in the upper-right corner of the pane).

In the "Alarm Settings" window:
Select the "Enable Alarms" box.
In the "Traffic Log DB" field, enter "75".
In the "Threat Log DB" field, enter "75".
In the "Configuration Log DB" field, enter "75".
In the "System Log DB" field, enter "75".
In the "Alarm DB" field, enter "75".
In the "HIP Match Log DB" field, enter "75".
Select "OK".
Commit changes by selecting "Commit" in the upper-right corner of the screen.  Select "OK" when the confirmation dialog appears.'
  impact 0.3
  ref 'DPMS Target Palo Alto Networks Security Platform NDM'
  tag check_id: 'C-63557r1_chk'
  tag severity: 'low'
  tag gid: 'V-62749'
  tag rid: 'SV-77239r1_rule'
  tag stig_id: 'PANW-NM-000096'
  tag gtitle: 'SRG-APP-000359-NDM-000294'
  tag fix_id: 'F-68669r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
end
