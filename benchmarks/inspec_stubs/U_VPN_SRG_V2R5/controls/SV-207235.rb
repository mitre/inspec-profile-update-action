control 'SV-207235' do
  title 'The VPN Gateway must generate a log record or an SNMP trap that can be forwarded as an alert to, at a minimum, the SCA and ISSO, of all log failure events where the detection and/or prevention function is unable to write events to either local storage or the centralized server.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected.

Alerts provide organizations with urgent messages. Automated alerts can be conveyed in a variety of ways, including, for example, telephonically, via electronic mail, via text message, or via websites. Log processing failures include software/hardware errors, failures in the log capturing mechanisms, and log storage capacity being reached or exceeded.

While this requirement also applies to the event monitoring system (e.g., Syslog, Security Information and Event Management [SIEM], or SNMP servers), the VPN Gateway must also be configured to generate a message to the administrator console.

The VPN daemon facility and log facility are messages in the log, which capture actions performed or errors encountered by system processes.'
  desc 'check', 'Verify the VPN Gateway generates a log record or an SNMP trap that can be forwarded as an alert to, at a minimum, the SCA and ISSO, of all log failure events where the detection and/or prevention function is unable to write events to either local storage or the centralized server.

If the VPN Gateway does not generate a log record or an SNMP trap that can be forwarded as an alert to, at a minimum, the SCA and ISSO, of all log failure events where the detection and/or prevention function is unable to write events to either local storage or the centralized server, this is a finding.'
  desc 'fix', 'Configure the VPN Gateway to generate a log record or an SNMP trap that can be forwarded as an alert to, at a minimum, the SCA and ISSO, of all log failure events where the detection and/or prevention function is unable to write events to either local storage or the centralized server.'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7495r378326_chk'
  tag severity: 'medium'
  tag gid: 'V-207235'
  tag rid: 'SV-207235r878129_rule'
  tag stig_id: 'SRG-NET-000335-VPN-001270'
  tag gtitle: 'SRG-NET-000335'
  tag fix_id: 'F-7495r378327_fix'
  tag 'documentable'
  tag legacy: ['SV-106287', 'V-97149']
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
