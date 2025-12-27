control 'SV-253932' do
  title 'The Juniper EX switch must be configured to generate audit records when deleting administrator privileges.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the network device (e.g., module or policy filter).'
  desc 'check', 'Determine if the network device generates audit records when deleting administrator privileges.

Verify the system logs the facility "any", or minimally "change-log" and "interactive-commands", and the logging level is appropriate. Generally, the "all" (debug) logging level should be avoided because the number of logged messages is significant.

[edit system syslog]
host <IPv4 or IPv6 syslog address> {
    any info;
}
file <file name> {
    change-log info;
    interactive-commands info;
}
Note: If minimally logging only configuration changes, there will be other files receiving the events from the other logging facilities (for example "authorizations" or "firewall").

Syslog outputs in standard format unless the "structured-data" directive is configured. Verify the "structured-data" command for all files and external syslog servers requiring that format. For example:

[edit system syslog]
host <IPv4 or IPv6 syslog address> {
    change-log info;
    interactive-commands info;
    structured-data;
}
file <file name> {
    any info;
    structured-data;
}

If the network device does not generate audit records when deleting administrator privileges, this is a finding.'
  desc 'fix', 'Configure the network device to generate audit records when deleting administrator privileges.

set system syslog host <IPv4 or IPv6 syslog address> change-log info
set system syslog host <IPv4 or IPv6 syslog address> interactive-commands info
-or-
set system syslog host <IPv4 or IPv6 syslog address> any info

set system syslog file <file name> change-log info
set system syslog file <file name> interactive-commands info
-or-
set system syslog file <file name> any info'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches NDM'
  tag check_id: 'C-57384r843827_chk'
  tag severity: 'medium'
  tag gid: 'V-253932'
  tag rid: 'SV-253932r843829_rule'
  tag stig_id: 'JUEX-NM-000550'
  tag gtitle: 'SRG-APP-000499-NDM-000319'
  tag fix_id: 'F-57335r843828_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
