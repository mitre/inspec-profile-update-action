control 'SV-253934' do
  title 'The Juniper EX switch must be configured to generate audit records for privileged activities or other system-level access.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the network device (e.g., module or policy filter).'
  desc 'check', 'Determine if the network device generates audit records for privileged activities or other system-level access.

Junos logs all completed commands via the "interactive-commands" syslog facility and all configuration changes via "change-log". Successful and unsuccessful login attempts are logged using the "authorization" facility. Verify syslog is configured to capture these facilities using the logging level "info" or above. The lowest logging level, "any", is debug and will generate significant numbers of messages. The "any" logging facility (not to be confused with the severity level "any")  includes authorization, change-log, and interactive-commands.

Example configuration to generate audit records for privileged activities or other system-level access.

[edit system syslog]
file <file name> {
    authorization info;
    change-log info;
    interactive-commands info;
}
host <syslog address> {
    any info;
    explicit-priority;
}
time-format year millisecond;
Note: The time-format command supports including the year and/or the time in milliseconds (both shown for clarity). The default format does not include the year and time is recorded in seconds. 

Syslog outputs in standard format unless the "structured-data" directive is configured. Verify the "structured-data" command for all files and external syslog servers requiring that format. For example:

[edit system syslog]
host <syslog address> {
    authorization info;
    change-log info;
    interactive-commands info;
    structured-data;
}
file <file name> {
    any info;
    structured-data;
}

If the network device does not generate audit records for privileged activities or other system-level access, this is a finding.'
  desc 'fix', 'Configure the network device to generate audit records for privileged activities or other system-level access.

set system syslog host <syslog address> any info
set system syslog host <syslog address> explicit-priority
set system syslog file <file name> any info
set system syslog time-format year'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches NDM'
  tag check_id: 'C-57386r843833_chk'
  tag severity: 'medium'
  tag gid: 'V-253934'
  tag rid: 'SV-253934r879875_rule'
  tag stig_id: 'JUEX-NM-000570'
  tag gtitle: 'SRG-APP-000504-NDM-000321'
  tag fix_id: 'F-57337r843834_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
