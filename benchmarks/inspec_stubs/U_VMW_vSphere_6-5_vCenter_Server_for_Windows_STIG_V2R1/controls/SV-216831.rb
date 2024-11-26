control 'SV-216831' do
  title 'The vCenter Server for Windows must provide an immediate real-time alert to the SA and ISSO, at a minimum, of all audit failure events.'
  desc 'It is critical for the appropriate personnel to be aware if an ESXi host is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability, and system operation may be adversely affected.

To ensure the appropriate personnel are alerted if an audit failure occurs a vCenter alarm can be created to trigger when an ESXi host can no longer reach its syslog server.'
  desc 'check', 'From the vSphere Web Client go to Host and Clusters >> Select a vCenter Server >> Monitor >> Issues >> Alarm Definitions. Verify there is an alarm created to alert when an ESXi host can no longer reach its syslog server.

or

From a PowerCLI command prompt while connected to the vCenter server run the following command:

Get-AlarmDefinition | Where {$_.ExtensionData.Info.Expression.Expression.EventTypeId -eq "esx.problem.vmsyslogd.remote.failure"} | Select Name,Enabled,@{N="EventTypeId";E={$_.ExtensionData.Info.Expression.Expression.EventTypeId}}

If an alarm is not created to alert when syslog failures occur, this is a finding.'
  desc 'fix', 'From the vSphere Web Client go to Host and Clusters >> Select a vCenter Server >> Monitor >> Issues >> Alarm Definitions >> Click the green plus icon. Provide an alarm name and description, Select "Hosts" from the "Monitor" dropdown menu. Select "specific event" next to "Monitor for". Enable the alarm. Click "Next". Add a new Trigger and paste in "esx.problem.vmsyslogd.remote.failure" for the Event. Select "Alert" for the Status. Click "Next". Add an action to send an email or a trap for "green to yellow" and "yellow to red" categories, configure appropriately. Click "Finish".

Note - This alarm will only trigger if syslog is configured for TCP or SSL connections and not UDP.'
  impact 0.3
  ref 'DPMS Target VMW vSphere 6.5 vCenter Server for Windows'
  tag check_id: 'C-18062r366207_chk'
  tag severity: 'low'
  tag gid: 'V-216831'
  tag rid: 'SV-216831r612237_rule'
  tag stig_id: 'VCWN-65-000008'
  tag gtitle: 'SRG-APP-000108'
  tag fix_id: 'F-18060r366208_fix'
  tag 'documentable'
  tag legacy: ['V-94729', 'SV-104559']
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end
