control 'SV-239948' do
  title 'The Cisco ASA must be configured to generate an alert that can be forwarded as an alert to organization-defined personnel and/or firewall administrator of all log failure events.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected.

Alerts provide organizations with urgent messages. Automated alerts can be conveyed in a variety of ways, including, for example, telephonically, via electronic mail, via text message, or via websites. Log processing failures include software/hardware errors, failures in the log capturing mechanisms, and log storage capacity being reached or exceeded.

While this requirement also applies to the event monitoring system (e.g., Syslog, Security Information and Event Management [SIEM], or SNMP servers), the VPN Gateway must also be configured to generate a message to the administrator console.

The VPN daemon facility and log facility are messages in the log, which capture actions performed or errors encountered by system processes. The ISSM or ISSO may designate the firewall/system administrator or other authorized personnel to receive the alert within the specified time, validate the alert, then forward only validated alerts to the ISSM and ISSO.'
  desc 'check', 'Review the Cisco ASA configuration to verify that it is compliant with this requirement as shown in the example below.

logging trap critical
logging host NDM_INTERFACE 10.1.48.10 6/1514

Note: The parameter "critical" can replaced with a lesser severity (i.e., error, warning, notice, informational). A logging list can be used as an alternative to the severity level.

If the Cisco ASA is not configured to generate an alert that can be forwarded to organization-defined personnel and/or firewall administrator of all log failure events, this is a finding.'
  desc 'fix', 'Configure the Cisco ASA to send critical to emergency log messages to the syslog server as shown in the example below.

ASA(config)# logging host NDM_INTERFACE 10.1.48.10 6/1514
ASA(config)# logging trap critical
ASA(config)# end

Note: The parameter "critical" can replaced with a lesser severity (i.e., error, warning, notice, informational). A logging list can be used as an alternative to the severity level.'
  impact 0.5
  ref 'DPMS Target Cisco ASA VPN'
  tag check_id: 'C-43181r666248_chk'
  tag severity: 'medium'
  tag gid: 'V-239948'
  tag rid: 'SV-239948r878129_rule'
  tag stig_id: 'CASA-VN-000090'
  tag gtitle: 'SRG-NET-000335-VPN-001270'
  tag fix_id: 'F-43140r666249_fix'
  tag 'documentable'
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
