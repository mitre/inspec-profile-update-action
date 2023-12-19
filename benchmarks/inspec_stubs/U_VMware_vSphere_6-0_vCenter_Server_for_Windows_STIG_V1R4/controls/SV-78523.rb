control 'SV-78523' do
  title 'The system must alert administrators on permission deletion operations.'
  desc 'If personnel are not notified of permission events, they will not be aware of possible unsecure situations.'
  desc 'check', 'From the vSphere Client select the vCenter server at the top of the hierarchy and go to >> Alarms >> Definitions.  Verify there is an alarm created to alert on permission deletions.

or

From a PowerCLI command prompt while connected to the vCenter server run the following command:

Get-AlarmDefinition | Where {$_.ExtensionData.Info.Expression.Expression.EventTypeId -eq "vim.event.PermissionRemovedEvent"} | Select Name,Enabled,@{N="EventTypeId";E={$_.ExtensionData.Info.Expression.Expression.EventTypeId}}

If an alarm is not created to alert on permission deletion events, this is a finding.'
  desc 'fix', 'From the vSphere Client select the vCenter server at the top of the hierarchy and go to >> Alarms >> Definitions >> Right click in the empty space and select New Alarm.  On the General tab provide an alarm name and description, Select vCenter for alarm type and "Monitor for specific events occurring on this object", check "Enable this alarm".  On the Triggers tab click Add three triggers and in the event column enter "vim.event.PermissionAddedEvent", "vim.event.PermissionRemovedEvent", and "vim.event.PermissionUpdatedEvent" for the three triggers and click OK.'
  impact 0.5
  ref 'DPMS Target vCenter Server 6.0'
  tag check_id: 'C-64785r1_chk'
  tag severity: 'medium'
  tag gid: 'V-64033'
  tag rid: 'SV-78523r1_rule'
  tag stig_id: 'VCWN-06-000049'
  tag gtitle: 'SRG-APP-000275'
  tag fix_id: 'F-69963r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001294']
  tag nist: ['SI-6 c']
end
