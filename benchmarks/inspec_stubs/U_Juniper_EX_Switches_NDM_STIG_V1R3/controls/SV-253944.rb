control 'SV-253944' do
  title 'The Juniper EX switch must be configured to send log data to a central log server for the purpose of forwarding alerts to the administrators and the ISSO.'
  desc 'The aggregation of log data kept on a syslog server can be used to detect attacks and trigger an alert to the appropriate security personnel. The stored log data can used to detect weaknesses in security that enable the network IA team to find and address these weaknesses before breaches can occur. Reviewing these logs, whether before or after a security breach, are important in showing whether someone is an internal employee or an outside threat.'
  desc 'check', 'Verify that the network device is configured to send log data to a central log server. 

Verify the external syslog server is configured. The lowest severity level, "any", is debug and will generate a significant number of messages.

[edit system syslog]
host <external syslog address> {
    any info;
    structured-format; << Only if structured formatting is required, otherwise events are recorded in standard format.
}
time-format year;
Note: The time-format command supports including the year and/or the time in milliseconds. The default format does not include the year and time is recorded in seconds.

If the network device is not configured to send log data to a central log server, this is a finding.'
  desc 'fix', 'Configure the network device to send log data to a central log server.

set system syslog host <external syslog IPv4 or IPv6 address> any info'
  impact 0.7
  ref 'DPMS Target Juniper EX Series Switches NDM'
  tag check_id: 'C-57396r843863_chk'
  tag severity: 'high'
  tag gid: 'V-253944'
  tag rid: 'SV-253944r879887_rule'
  tag stig_id: 'JUEX-NM-000670'
  tag gtitle: 'SRG-APP-000516-NDM-000350'
  tag fix_id: 'F-57347r843864_fix'
  tag 'documentable'
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
