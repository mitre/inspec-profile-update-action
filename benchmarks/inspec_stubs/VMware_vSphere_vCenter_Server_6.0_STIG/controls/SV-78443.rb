control 'SV-78443' do
  title 'The system must provide an immediate real-time alert to the SA and ISSO, at a minimum, of all audit failure events.'
  desc 'It is critical for the appropriate personnel to be aware if an ESXi host is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability, and system operation may be adversely affected.

To ensure the appropriate personnel are alerted if an audit failure occurs a vCenter alarm can be created to trigger when an ESXi host can no longer reach its syslog server.'
  desc 'check', 'From the vSphere Client select the vCenter server at the top of the hierarchy and go to >> Alarms >> Definitions.  Verify there is an alarm created to alert if an ESXi host can no longer reach its syslog server.

or

From a PowerCLI command prompt while connected to the vCenter server run the following command:

Get-AlarmDefinition | Where {$_.ExtensionData.Info.Expression.Expression.EventTypeId -eq "esx.problem.vmsyslogd.remote.failure"} | Select Name,Enabled,@{N="EventTypeId";E={$_.ExtensionData.Info.Expression.Expression.EventTypeId}}

If an alarm is not created to alert when syslog failures occur, this is a finding.'
  desc 'fix', 'From the vSphere Client select the vCenter server at the top of the hierarchy and go to >> Alarms >> Definitions >> Right click in the empty space and select New Alarm.  On the General tab provide an alarm name and description, Select Hosts for alarm type and "Monitor for specific events occurring on this object", check "Enable this alarm".  On the Triggers tab click Add and in the event column enter "esx.problem.vmsyslogd.remote.failure" and click OK.

Note - This alarm will only trigger if syslog is configured for TCP or SSL connections and not UDP.'
  impact 0.3
  ref 'DPMS Target vCenter Server 6.0'
  tag check_id: 'C-64703r1_chk'
  tag severity: 'low'
  tag gid: 'V-63953'
  tag rid: 'SV-78443r1_rule'
  tag stig_id: 'VCWN-06-000008'
  tag gtitle: 'SRG-APP-000108'
  tag fix_id: 'F-69881r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end
