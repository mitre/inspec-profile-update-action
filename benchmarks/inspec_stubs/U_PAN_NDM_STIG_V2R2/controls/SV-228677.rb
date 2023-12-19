control 'SV-228677' do
  title 'The Palo Alto Networks security platform must generate an audit log record when the Data Plane CPU utilization is 100%.'
  desc 'Auditing and logging are key components of any security architecture. Logging the actions of specific events provides a means to investigate an attack; to recognize resource utilization or capacity thresholds; or to identify an improperly configured network device. If auditing is not comprehensive, it will not be useful for intrusion monitoring, security investigations, and forensic analysis.

If the Data Plane CPU utilization is 100%, this may indicate an attack or simply an over-utilized device.  In either case, action must be taken to identify the source of the issue and take corrective action.'
  desc 'check', 'Go to Device >> Setup >> Management
In the "Logging and Reporting Settings" pane.
If the "Enable Log on High DP Load" check box is not selected, this is a finding.'
  desc 'fix', 'Go to Device >> Setup >> Management
In the "Logging and Reporting Settings" pane, select the "Edit" icon (the gear symbol in the upper-right corner of the pane).
In the "Log Export and Reporting" tab, select the "Enable Log on High DP Load" check box.  
Select "OK".
Commit changes by selecting "Commit" in the upper-right corner of the screen.
Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks NDM'
  tag check_id: 'C-30912r513634_chk'
  tag severity: 'medium'
  tag gid: 'V-228677'
  tag rid: 'SV-228677r513636_rule'
  tag stig_id: 'PANW-NM-000144'
  tag gtitle: 'SRG-APP-000516-NDM-000334'
  tag fix_id: 'F-30889r513635_fix'
  tag 'documentable'
  tag legacy: ['SV-77273', 'V-62783']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
