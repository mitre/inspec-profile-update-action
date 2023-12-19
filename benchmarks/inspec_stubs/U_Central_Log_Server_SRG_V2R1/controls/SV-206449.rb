control 'SV-206449' do
  title 'The Central Log Server must be configured to aggregate log records from organization-defined devices and hosts within its scope of coverage.'
  desc 'If the application is not configured to collate records based on the time when the events occurred, the ability to perform forensic analysis and investigations across multiple components is significantly degraded. Centralized log aggregation must also include logs from databases and servers (e.g., Windows) that do not natively send logs using the syslog protocol.'
  desc 'check', 'Examine the documentation that lists the scope of coverage for the specific log server being reviewed.

Verify the system is configured to aggregate log records from organization-defined devices and hosts within its scope of coverage.

If the Central Log Server is not configured to aggregate log records from organization-defined devices and hosts within its scope of coverage, this is a finding.'
  desc 'fix', 'For each log server, configure the server to aggregate log records from organization-defined devices and hosts within its scope of coverage.'
  impact 0.3
  ref 'DPMS Target Central Log Server'
  tag check_id: 'C-6709r285591_chk'
  tag severity: 'low'
  tag gid: 'V-206449'
  tag rid: 'SV-206449r395700_rule'
  tag stig_id: 'SRG-APP-000086-AU-000020'
  tag gtitle: 'SRG-APP-000086'
  tag fix_id: 'F-6709r285592_fix'
  tag 'documentable'
  tag legacy: ['SV-95821', 'V-81107']
  tag cci: ['CCI-000174']
  tag nist: ['AU-12 (1)']
end
