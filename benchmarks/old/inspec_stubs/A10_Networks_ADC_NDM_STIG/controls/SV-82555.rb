control 'SV-82555' do
  title 'The A10 Networks ADC must generate alerts to the administrators and ISSO when accounts are disabled.'
  desc 'When application accounts are disabled, administrator accessibility is affected. Accounts are utilized for identifying individual device administrators or for identifying the device processes themselves. 

In order to detect and respond to events that affect administrator accessibility and device processing, devices must audit account disabling actions and, as required, notify the appropriate individuals so they can investigate the event. Such a capability greatly reduces the risk that device accessibility will be negatively affected for extended periods of time and also provides logging that can be used for forensic purposes.

The A10 Networks ADC records in the audit log when an account is disabled. This appears as the command that created the account and contains the keyword "admin". These messages must be forwarded to the ISSO and administrators. Configuring the device to forward all audit log messages to an actively monitored syslog server or SNMP management station meets this requirement.'
  desc 'check', 'The A10 Networks ADC records in the audit log when an account is disabled. This appears as the command that created the account and contains the keyword "admin". These messages must be forwarded to the ISSO and administrators. This is met by sending audit log messages to the Syslog servers or SNMP management station, which is continuously monitored.

Review the device configuration.

The following command shows the portion of the device configuration that includes the word "host":
show run | inc host

If the output does not display the "logging host" and "logging auditlog host" commands (no log targets are configured), this is a finding.

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
  tag check_id: 'C-68625r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68065'
  tag rid: 'SV-82555r1_rule'
  tag stig_id: 'AADC-NM-000080'
  tag gtitle: 'SRG-APP-000293-NDM-000277'
  tag fix_id: 'F-74181r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001685']
  tag nist: ['AC-2 (4)']
end
