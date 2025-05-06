control 'SV-82561' do
  title 'The A10 Networks ADC must notify System Administrators (SAs) and Information System Security Officers (ISSMs) when accounts are created, or enabled when previously disabled.'
  desc 'Once an attacker establishes initial access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to simply enable a new or disabled account. Notification of account enabling is one method for mitigating this risk. A comprehensive account management process will ensure an audit trail which documents the creation of application user accounts and notifies SAs and ISSMs. Such a process greatly reduces the risk that accounts will be surreptitiously enabled and provides logging that can be used for forensic purposes.

In order to detect and respond to events that affect network administrator accessibility and device processing, network devices must audit account enabling actions and, as required, notify the appropriate individuals so they can investigate the event.'
  desc 'check', 'The A10 Networks ADC records in the audit log when an account is created (enabled). This appears as the command that created the account and contains the keyword "admin". These messages must be forwarded to the ISSO and administrators. This is met by sending audit log messages to the Syslog servers. 

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
  tag check_id: 'C-68631r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68071'
  tag rid: 'SV-82561r1_rule'
  tag stig_id: 'AADC-NM-000087'
  tag gtitle: 'SRG-APP-000320-NDM-000284'
  tag fix_id: 'F-74187r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002132']
  tag nist: ['AC-2 (4)']
end
