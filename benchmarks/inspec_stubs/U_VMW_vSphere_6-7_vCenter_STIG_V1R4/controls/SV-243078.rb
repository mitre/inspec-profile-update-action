control 'SV-243078' do
  title 'The vCenter Server must provide an immediate real-time alert to the SA and ISSO, at a minimum, of all audit failure events.'
  desc 'It is critical for the appropriate personnel to be aware if an ESXi host is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability, and system operation may be adversely affected.

To ensure the appropriate personnel are alerted if an audit failure occurs, a vCenter alarm can be created to trigger when an ESXi host can no longer reach its syslog server.'
  desc 'check', 'From the vSphere Client, go to Hosts and Clusters >> select a vCenter Server >> Configure >> More >> Alarm Definitions. 

Verify there is an alarm created to alert if an ESXi host can no longer reach its syslog server. The alarm definition will have a rule for the "Remote logging host has become unreachable" event.

or

From a PowerCLI command prompt while connected to the vCenter server, run the following command:

Get-AlarmDefinition | Where {$_.ExtensionData.Info.Expression.Expression.EventTypeId -eq "esx.problem.vmsyslogd.remote.failure"} | Select Name,Enabled,@{N="EventTypeId";E={$_.ExtensionData.Info.Expression.Expression.EventTypeId}}

If an alarm is not created and enabled to alert when syslog failures occur, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Hosts and Clusters >> select a vCenter Server >> Configure >> More >> Alarm Definitions. 

Click "Add". 

Provide an alarm name and description.

Select "Hosts" from the "Target type" dropdown menu. 

Click "Next".

Paste "esx.problem.vmsyslogd.remote.failure" in the line after IF and press "Enter". 

Select "Show as Warning" for severity. 

Click "Next".

Configure any other options as desired, enable alarm, and finish.

Note: This alarm will only trigger if syslog is configured for TCP or SSL connections and not UDP.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 vCenter'
  tag check_id: 'C-46353r719475_chk'
  tag severity: 'medium'
  tag gid: 'V-243078'
  tag rid: 'SV-243078r879570_rule'
  tag stig_id: 'VCTR-67-000008'
  tag gtitle: 'SRG-APP-000108'
  tag fix_id: 'F-46310r719643_fix'
  tag 'documentable'
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end
