control 'SV-251663' do
  title 'Splunk Enterprise must be configured to aggregate log records from organization-defined devices and hosts within its scope of coverage.'
  desc 'If the application is not configured to collate records based on the time when the events occurred, the ability to perform forensic analysis and investigations across multiple components is significantly degraded. Centralized log aggregation must also include logs from databases and servers (e.g., Windows) that do not natively send logs using the syslog protocol.'
  desc 'check', 'Examine the site documentation that lists the scope of coverage for the instance being reviewed.

Select Settings >> Data Inputs. Verify that data inputs are configured to support the scope of coverage documented for the site.

If Splunk enterprise is not configured to aggregate log records from organization-defined devices and hosts within its scope of coverage, this is a finding.'
  desc 'fix', 'Configure Splunk Enterprise to aggregate log records from organization-defined devices and hosts within its scope of coverage, as defined in the site security plan.'
  impact 0.3
  ref 'DPMS Target Splunk Enterprise 8.x for Linux'
  tag check_id: 'C-55101r808223_chk'
  tag severity: 'low'
  tag gid: 'V-251663'
  tag rid: 'SV-251663r808225_rule'
  tag stig_id: 'SPLK-CL-000100'
  tag gtitle: 'SRG-APP-000086-AU-000020'
  tag fix_id: 'F-55055r808224_fix'
  tag 'documentable'
  tag cci: ['CCI-000174']
  tag nist: ['AU-12 (1)']
end
