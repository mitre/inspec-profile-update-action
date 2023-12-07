control 'SV-216869' do
  title 'The vCenter Server for Windows must alert administrators on permission update operations.'
  desc 'If personnel are not notified of permission events, they will not be aware of possible unsecure situations.'
  desc 'check', '"From the vSphere Web Client go to Host and Clusters >> Select a vCenter Server >> Monitor >> Issues >> Alarm Definitions. 

Verify there is an alarm created to alert on permission additions.

or

From a PowerCLI command prompt while connected to the vCenter server run the following command:
Get-AlarmDefinition | Where {$_.ExtensionData.Info.Expression.Expression.EventTypeId -eq ""vim.event.PermissionUpdatedEvent""} | Select Name,Enabled,@{N=""EventTypeId"";E={$_.ExtensionData.Info.Expression.Expression.EventTypeId}}

If an alarm is not created to alert on permission addition events, this is a finding."'
  desc 'fix', 'From the vSphere Web Client select the vCenter server at the top of the hierarchy and go to >> Alarms >> Definitions. Right-click in the empty space and select "New Alarm". On the "General" tab provide an alarm name and description, Select "vCenter Server" for alarm type and "Monitor for specific events occurring on this object", check "Enable this alarm". On the "Triggers" tab, click "Add" for a trigger and in the event column enter "vim.event.PermissionUpdatedEvent" and click "OK".'
  impact 0.5
  ref 'DPMS Target VMW vSphere 6.5 vCenter Server for Windows'
  tag check_id: 'C-18100r366321_chk'
  tag severity: 'medium'
  tag gid: 'V-216869'
  tag rid: 'SV-216869r879661_rule'
  tag stig_id: 'VCWN-65-000050'
  tag gtitle: 'SRG-APP-000275'
  tag fix_id: 'F-18098r366322_fix'
  tag 'documentable'
  tag legacy: ['SV-104633', 'V-94803']
  tag cci: ['CCI-001294']
  tag nist: ['SI-6 c']
end
