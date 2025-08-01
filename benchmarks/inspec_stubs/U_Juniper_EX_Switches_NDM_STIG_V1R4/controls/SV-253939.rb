control 'SV-253939' do
  title 'The Juniper EX switch must be configured to generate log records for a locally developed list of auditable events.'
  desc 'Auditing and logging are key components of any security architecture. Logging the actions of specific events provides a means to investigate an attack; to recognize resource utilization or capacity thresholds; or to identify an improperly configured network device. If auditing is not comprehensive, it will not be useful for intrusion monitoring, security investigations, and forensic analysis.'
  desc 'check', 'Determine if the network device generates audit log events for a locally developed list of auditable events.

Verify audit logging is enabled.
[edit system syslog]
file <file name> {
    any info;
}
host <external syslog address> {
    any info;
}
time-format year;

Note: Without the "structured-data" directive (as shown), syslog outputs in standard format. Add the "structured-data" command to all files and external syslog servers requiring that format. For example:
[edit system syslog]
file <file name> {
    any info;
    structured-data;
}

If the logging facility and level is too broad, Junos supports REGEX or string match conditions to filter events. If used, verify the match conditions capture the required events.
[edit system syslog]
file <file name> {
    any info;
    match <REGEX>;
    -or-
    match-strings [ "string 1" "string 2" ];
}
Note: When using match conditions, it may be necessary to use the "any" (debug) severity level, but this should not generate overwhelming numbers of messages because the filter will ignore all unmatched events.

If the network device is not configured to generate audit log events for a locally developed list of auditable events, this is a finding.'
  desc 'fix', 'Configure the network device to generate audit log events for a locally developed list of auditable events.

set system syslog file <file name> messages any info
set system syslog file <file name> structured-data << (Optional) Only if structured data format is required
set system syslog host <external syslog address> any info
set system syslog host <external syslog address> structured-data << (Optional) Only if structured data format is required
set system syslog time-format year

If using REGEX or string match conditions:
set system syslog file <name> any <info|any>
set system syslog file <name> match <REGEX>
-or-
set system syslog file <name> match-strings [ "string 1" "string 2" ]'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches NDM'
  tag check_id: 'C-57391r843848_chk'
  tag severity: 'medium'
  tag gid: 'V-253939'
  tag rid: 'SV-253939r879887_rule'
  tag stig_id: 'JUEX-NM-000620'
  tag gtitle: 'SRG-APP-000516-NDM-000334'
  tag fix_id: 'F-57342r843849_fix'
  tag 'documentable'
  tag cci: ['CCI-000169', 'CCI-000366']
  tag nist: ['AU-12 a', 'CM-6 b']
end
