control 'SV-253935' do
  title 'The Juniper EX switch must be configured to generate audit records showing starting and ending time for administrator access to the system.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the network device (e.g., module or policy filter).'
  desc 'check', 'Determine if the network device generates audit records showing starting and ending time for administrator access to the system.

Junos logs all logon attempts via the "authorization" syslog facility. Verify logging level "any info" or "authorization info" is configured. Time stamps are created for every log entry, both successful and failed logon attempts, and logout.

[edit system syslog]
file <file name> {
    any info;
}
host <external syslog address> {
    any info;
}
time-format year millisecond;

Syslog outputs in standard format unless the "structured-data" directive is configured. Verify the "structured-data" command for all files and external syslog servers requiring that format. For example:

[edit system syslog]
host <syslog address> {
    change-log info;
    interactive-commands info;
    structured-data;
}
file <file name> {
    any info;
    structured-data;
}

If the network device does not generate audit records showing starting and ending time for administrator access to the system, this is a finding.'
  desc 'fix', 'Configure the network device to generate audit records showing starting and ending time for administrator access to the system.

set system syslog file <file name> any info
set system syslog host <external syslog address> any info
set system syslog time-format year'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches NDM'
  tag check_id: 'C-57387r843836_chk'
  tag severity: 'medium'
  tag gid: 'V-253935'
  tag rid: 'SV-253935r843838_rule'
  tag stig_id: 'JUEX-NM-000580'
  tag gtitle: 'SRG-APP-000505-NDM-000322'
  tag fix_id: 'F-57338r843837_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
