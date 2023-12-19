control 'SV-80969' do
  title 'The Juniper SRX Services Gateway must generate an immediate system alert message to the management console when a log processing failure is detected.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process logs as required. Without an immediate alert for critical system issues, security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected.

Alerts provide organizations with urgent messages. Real-time alerts provide these messages at information technology speed (i.e., the time from event detection to alert occurs in seconds or less). Automated alerts can be conveyed in a variety of ways, including, for example, telephonically, via electronic mail, via text message, or via websites.

Alerts must be sent immediately to the designated individuals (e.g., via Syslog configuration, SNMP trap, manned console message, or other events monitoring system). 

Log processing failures include software/hardware errors, failures in the log capturing mechanisms, and log storage capacity being reached or exceeded.

While this requirement also applies to the configuration of the event monitoring system (e.g., Syslog, Security Information and Event Management [SIEM], or SNMP servers), the Juniper SRX can also be configured to generate a message to the administrator console or send via email for immediate messages.

Syslog and SNMP trap events with a facility of "daemon" pertaining to errors encountered by system processes.'
  desc 'check', 'Verify the system Syslog has been configured to display an alert on the console for the emergency and critical levels of the daemon facility.

[edit] 
show system syslog

If the system is not configured to generate a system alert message when a component failure is detected, this is a finding.'
  desc 'fix', "The following commands configure syslog to immediately display any emergency level or daemon alert events to the management console. The message will display on any currently logged on administrator's console. This is an example method. Alerts must be sent immediately to the designated individuals (e.g., via Syslog configuration, SNMP trap, manned console message, or other events monitoring system). 

[edit]
set system syslog user * any emergency
set system syslog user * daemon alert
set system syslog user * daemon critical"
  impact 0.5
  ref 'DPMS Target Juniper SRX SG NDM'
  tag check_id: 'C-67125r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66479'
  tag rid: 'SV-80969r1_rule'
  tag stig_id: 'JUSX-DM-000059'
  tag gtitle: 'SRG-APP-000360-NDM-000295'
  tag fix_id: 'F-72555r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
