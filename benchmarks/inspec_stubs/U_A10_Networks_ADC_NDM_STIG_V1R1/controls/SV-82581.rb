control 'SV-82581' do
  title 'The A10 Networks ADC must off-load audit records onto a different system or media than the system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.'
  desc 'check', 'Review the device configuration.

The following command shows the portion of the device configuration that includes the word "host":
show run | inc host

If the output does not display the "logging host" and "logging auditlog host" commands, this is a finding.

The following command shows the logging policy:
show log policy

If Syslog logging is disabled, this is a finding.'
  desc 'fix', 'The following command specifies the severity levels of event messages to send to a Syslog server:
logging syslog [severity-level]

The following command specifies a Syslog server to which to send event messages:
logging host ipaddr [ipaddr...][port protocol-port]
"ipaddr" is the IP address of the Syslog server. IP addresses can be entered for up to 10 remote logging Syslog servers.
"protocolport" is the port number to which to send messages. Only one protocol port can be specified with the command. All servers must use the same port to listen for syslog messages.

Since the Audit log is separate from the Event log, it must have its own target to write messages to:
logging auditlog host [ipaddr | hostname][facility facility-name]
"ipaddr | hostname" is the IP address or hostname of the server.
"facility-name" is the name of a log facility.'
  impact 0.5
  ref 'DPMS Target A10 Networks ADC NDM'
  tag check_id: 'C-68651r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68091'
  tag rid: 'SV-82581r1_rule'
  tag stig_id: 'AADC-NM-000130'
  tag gtitle: 'SRG-APP-000515-NDM-000325'
  tag fix_id: 'F-74205r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
