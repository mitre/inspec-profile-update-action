control 'SV-252199' do
  title 'The HPE Nimble must forward critical alerts (at a minimum) to the system administrators and the ISSO.'
  desc 'Alerts are essential to let the system administrators and security personnel know immediately of issues which may impact the system or users. If these alerts are also sent to the syslog, this information is used to detect weaknesses in security that enable the network IA team to find and address these weaknesses before breaches can occur. Reviewing these logs, whether before or after a security breach, are important in showing whether someone is an internal employee or an outside threat.

Alerts are identifiers about specific actions that occur on a group of arrays.

There are several ways to meet this requirement. The Nimble can be configured for forward alerts from groups to a secure Simple Mail Transfer Protocol (SMTP) server. The alert may also be sent to the syslog server and the syslog configured to send the alert to the appropriate personnel.'
  desc 'check', 'Type "group --info | grep -i syslog" and review the output lines. The "Syslogd enabled" value should be "Yes", and the "Syslogd server" and "Syslogd port" values should contain the correct syslog server and port values. If not, this is a finding.'
  desc 'fix', 'Configure email alerts (optional)
group--edit [--smtp_serversmtp server] [--smtp_portsmtp port] [--smtp_auth {yes | no}] [--smtp_username username]
--smtp_encrypt_type  ssl [--smtp_from_addr email addr] [--smtp_to_addr email addr]
[--send_event_data {yes | no}] [--alert_level {info | warning | critical}]

To specify and enable logging of alerts, type "group --edit --syslog_enabled yes --syslog_server <server> --syslog_port <port>", where <server> and <port> are the server DNS name or IP address, and <port> is the port to send syslog messages to.'
  impact 0.7
  ref 'DPMS Target HPE Nimble Storage Array'
  tag check_id: 'C-55655r814075_chk'
  tag severity: 'high'
  tag gid: 'V-252199'
  tag rid: 'SV-252199r814077_rule'
  tag stig_id: 'HPEN-NM-000140'
  tag gtitle: 'SRG-APP-000516-NDM-000350'
  tag fix_id: 'F-55605r814076_fix'
  tag 'documentable'
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
