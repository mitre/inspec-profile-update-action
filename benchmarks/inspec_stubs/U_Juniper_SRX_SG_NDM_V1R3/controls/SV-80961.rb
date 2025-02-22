control 'SV-80961' do
  title 'The Juniper SRX Services Gateway must generate an immediate alert message to the management console for account enabling actions.'
  desc 'In order to detect and respond to events that affect network administrator accessibility and device processing, network devices must audit account enabling actions and, as required, notify the appropriate individuals so they can investigate the event.

Alerts must be sent immediately to the designated individuals (e.g., via Syslog configuration, SNMP trap, manned console message, or other events monitoring system). 

Accounts can be disabled by configuring the account with the built-in login class "unauthorized". When the command is reissued with a different login class, the account is enabled.'
  desc 'check', 'Verify the device is configured to display change-log events of severity info.

[edit]
show system syslog

If the system is not configured to display account enabling actions on the management console, this is a finding.'
  desc 'fix', "The following commands configure the device to immediately display a message to any currently logged on administrator's console when changes are made to the configuration. This is an example method. Alerts must be sent immediately to the designated individuals (e.g., via Syslog configuration, SNMP trap, manned console message, or other events monitoring system). 

[edit]
set system syslog users * change-log <info | any>"
  impact 0.5
  ref 'DPMS Target Juniper SRX SG NDM'
  tag check_id: 'C-67117r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66471'
  tag rid: 'SV-80961r1_rule'
  tag stig_id: 'JUSX-DM-000024'
  tag gtitle: 'SRG-APP-000320-NDM-000284'
  tag fix_id: 'F-72547r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002132']
  tag nist: ['AC-2 (4)']
end
