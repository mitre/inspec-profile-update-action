control 'SV-252203' do
  title 'The HPE Nimble must configure a syslog server onto a different system or media than the system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

UDP is used to communicate between the array group and the syslog server (SSL is not supported at this time). This is an issue because DoD requires the use of TCP. One syslog message is generated for each alert and audit log message. Alert severity types include INFO, WARN, and ERROR.'
  desc 'check', 'Type "group --info | grep -i syslog" and review the output lines. The "Syslogd enabled" value should be "Yes", and the "Syslogd server" and "Syslogd port" values should contain the correct syslog server and port values. If not, this is a finding.'
  desc 'fix', 'To specify and enable logging of alerts, type "group --edit --syslog_enabled yes --syslog_server <server> --syslog_port <port>", where <server> and <port> are the server DNS name or IP address, and <port> is the port to send syslog messages to.'
  impact 0.5
  ref 'DPMS Target HPE Nimble Storage Array'
  tag check_id: 'C-55659r814087_chk'
  tag severity: 'medium'
  tag gid: 'V-252203'
  tag rid: 'SV-252203r814089_rule'
  tag stig_id: 'HPEN-NM-000300'
  tag gtitle: 'SRG-APP-000515-NDM-000325'
  tag fix_id: 'F-55609r814088_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
