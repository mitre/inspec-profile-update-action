control 'SV-229028' do
  title 'The Juniper SRX Services Gateway must generate an alarm or send an alert message to the management console when a component failure is detected.'
  desc 'Component (e.g., chassis, file storage, file corruption) failure may cause the system to become unavailable, which could result in mission failure since the network would be operating without a critical security traffic inspection or access function.

Alerts provide organizations with urgent messages. Real-time alerts provide these messages at information technology speed (i.e., the time from event detection to alert occurs in seconds or less). Automated alerts can be conveyed in a variety of ways, including, for example, telephonically, via electronic mail, via text message, or via websites.

While this requirement also applies to the event monitoring system (e.g., Syslog, Security Information and Event Management [SIEM], or SNMP servers), the Juniper SRX must also be configured to generate a message to the administrator console.

Syslog and SNMP trap events with a facility of "daemon" pertain to errors encountered by system processes.'
  desc 'check', 'Verify the system Syslog has been configured to display an alert on the console for the emergency and critical levels of the daemon facility.

[edit] 
show system syslog

If the system is not configured to generate a system alert message when a component failure is detected, this is a finding.'
  desc 'fix', "The following commands configure syslog to immediately display any emergency level or daemon alert events to the management console. The message will display on any currently logged on administrator's console.

[edit]
set system syslog user * any emergency
set system syslog user * daemon critical
set system syslog user * daemon alert"
  impact 0.5
  ref 'DPMS Target Juniper SRX SG NDM'
  tag check_id: 'C-31343r518260_chk'
  tag severity: 'medium'
  tag gid: 'V-229028'
  tag rid: 'SV-229028r518262_rule'
  tag stig_id: 'JUSX-DM-000106'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-31320r518261_fix'
  tag 'documentable'
  tag legacy: ['V-66495', 'SV-80985']
  tag cci: ['CCI-000366', 'CCI-000372']
  tag nist: ['CM-6 b', 'CM-6 (1)']
end
