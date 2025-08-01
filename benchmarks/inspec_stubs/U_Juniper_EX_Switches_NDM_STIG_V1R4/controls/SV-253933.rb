control 'SV-253933' do
  title 'The Juniper EX switch must be configured to generate audit records when successful/unsuccessful logon attempts occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the network device (e.g., module or policy filter).'
  desc 'check', 'Determine if the network device generates audit records when successful/unsuccessful logon attempts occur.

Junos logs all logon attempts via the "authorization" syslog facility (or facility "any"). Verify logging level "any info" or "authorization info" is configured.

[edit system syslog]
file <file name> {
    authorization info;
}
host <external syslog address> {
    any info;
}
time-format year millisecond;
Syslog outputs in standard format unless the "structured-data" directive is configured. Verify the "structured-data" command for all files and external syslog servers requiring that format. For example:

[edit system syslog]
host <syslog address> {
    authorization info;
    structured-data;
}
file <file name> {
    any info;
    structured-data;
}

If it does not generate audit records when successful/unsuccessful logon attempts occur, this is a finding.'
  desc 'fix', 'Configure the network device to generate audit records when successful/unsuccessful logon attempts occur.

set system syslog file <file name> any info
set system syslog file <file name> structured-data << (Optional) Only if structured data format is required
set system syslog host <external syslog address> authorization info
set system syslog host <external syslog address> structured-data << (Optional) Only if structured data format is required
set system syslog time-format <(year|millisecond)>'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches NDM'
  tag check_id: 'C-57385r843830_chk'
  tag severity: 'medium'
  tag gid: 'V-253933'
  tag rid: 'SV-253933r879874_rule'
  tag stig_id: 'JUEX-NM-000560'
  tag gtitle: 'SRG-APP-000503-NDM-000320'
  tag fix_id: 'F-57336r843831_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
