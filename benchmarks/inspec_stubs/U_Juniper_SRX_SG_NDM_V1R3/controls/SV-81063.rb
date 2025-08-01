control 'SV-81063' do
  title 'For local logging, the Juniper SRX Services Gateway must generate a message to the system management console when a log processing failure occurs.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process logs as required. Without this alert, the security personnel may be unaware of an impending failure of the log capability and system operation may be adversely affected. 

Alerts provide organizations with urgent messages. Real-time alerts provide these messages at information technology speed (i.e., the time from event detection to alert occurs in seconds or less). Automated alerts can be conveyed in a variety of ways, including, for example, telephonically, via electronic mail, via text message, or via websites.

Log processing failures include software/hardware errors, failures in the log capturing mechanisms, and log storage capacity being reached or exceeded.

While this requirement also applies to the event monitoring system (e.g., Syslog, Security Information and Event Management [SIEM], or SNMP servers), the Juniper SRX must also be configured to generate a message to the administrator console.

Syslog and SNMP trap events with a facility of "daemon" pertain to errors encountered by system processes.'
  desc 'check', 'Verify the system Syslog has been configured to display an alert on the console for the emergency and alert levels of the daemon facility.

[edit] 
show system syslog

If the system is not configured to generate a message to the system management console when a log processing failure occurs, this is a finding.'
  desc 'fix', "The following commands configure syslog to immediately display any emergency level or daemon alert events to the management console. The message will display on any currently logged on administrator's console.

[edit]
set system syslog user * any emergency
set system syslog user * daemon alert
set system syslog user * daemon critical"
  impact 0.3
  ref 'DPMS Target Juniper SRX SG NDM'
  tag check_id: 'C-67219r1_chk'
  tag severity: 'low'
  tag gid: 'V-66573'
  tag rid: 'SV-81063r1_rule'
  tag stig_id: 'JUSX-DM-000060'
  tag gtitle: 'SRG-APP-000108-NDM-000232'
  tag fix_id: 'F-72649r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end
