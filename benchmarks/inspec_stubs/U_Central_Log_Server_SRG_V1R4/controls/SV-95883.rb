control 'SV-95883' do
  title 'The Central Log Server must be configured to generate reports that do not alter original content or time ordering of log records.'
  desc 'If the audit report generation capability alters the original content or time ordering of log records, the integrity of the log records is compromised, and the records are no longer usable for forensic analysis. Time ordering refers to the chronological organization of records based on time stamps. The degree of time stamp precision can affect this.

The report generation capability provided by the application can generate customizable reports.

This requirement is specific to applications with audit reduction capabilities; however, applications need to support on-demand audit review and analysis.'
  desc 'check', 'Examine the configuration.

Verify the Central Log Server generates reports that do not alter original content or time ordering of log records.

If the Central Log Server is not configured to generate reports that do not alter original content or time ordering of log records, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to generate reports that do not alter original content or time ordering of log records.'
  impact 0.3
  ref 'DPMS Target SRG-APP-LOG'
  tag check_id: 'C-80833r1_chk'
  tag severity: 'low'
  tag gid: 'V-81169'
  tag rid: 'SV-95883r1_rule'
  tag stig_id: 'SRG-APP-000370-AU-000260'
  tag gtitle: 'SRG-APP-000370-AU-000260'
  tag fix_id: 'F-87945r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001882']
  tag nist: ['AU-7 b']
end
