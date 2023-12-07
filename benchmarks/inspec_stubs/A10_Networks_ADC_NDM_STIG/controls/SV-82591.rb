control 'SV-82591' do
  title 'The A10 Networks ADC must use automated mechanisms to alert security personnel to threats identified by authoritative sources (e.g., CTOs) and IAW CJCSM 6510.01B.'
  desc 'By immediately displaying an alarm message, potential security violations can be identified more quickly even when administrators are not logged into the network device. An example of a mechanism to facilitate this would be through the use of SNMP traps or a Syslog server where messages are sent to an SNMP console or Syslog server that is monitored by the CNDSP.'
  desc 'check', 'Verify a log destination is configured for a CNDSP or other mechanism that is monitored by security personnel. Obtain the IP address of a Syslog server monitored by the CNDSP.

Review the device configuration.

The following command shows the portion of the device configuration that includes the word "host":
show run | inc host

If the output does not display the "logging host" and "logging auditlog host" commands, or does not include the IP address of the Syslog server used by the CNDSP, this is a finding.

The following command shows the logging policy:
show log policy

If Syslog logging is disabled, this is a finding.'
  desc 'fix', 'Obtain the IP address of a Syslog server monitored by the CNDSP.

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
  tag check_id: 'C-68661r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68101'
  tag rid: 'SV-82591r1_rule'
  tag stig_id: 'AADC-NM-000132'
  tag gtitle: 'SRG-APP-000516-NDM-000333'
  tag fix_id: 'F-74215r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001274']
  tag nist: ['CM-6 b', 'SI-4 (12)']
end
