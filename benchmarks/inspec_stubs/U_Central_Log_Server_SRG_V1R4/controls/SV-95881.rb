control 'SV-95881' do
  title 'The Central Log Server must be configured to perform audit reduction that does not alter original content or time ordering of log records.'
  desc 'If the audit reduction capability alters the content or time ordering of log records, the integrity of the log records is compromised, and the records are no longer usable for forensic analysis. Time ordering refers to the chronological organization of records based on time stamps. The degree of time stamp precision can affect this.

Audit reduction is a process that manipulates collected audit information and organizes such information in a summary format that is more meaningful to analysts.

This requirement is specific to applications with audit reduction capabilities; however, applications need to support on-demand audit review and analysis.'
  desc 'check', 'Examine the configuration.

Verify the Central Log Server performs audit reduction that does not alter original content or time ordering of log records.

If the Central Log Server is not configured to perform audit reduction that does not alter original content or time ordering of log records, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to perform audit reduction that does not alter original content or time ordering of log records.'
  impact 0.3
  ref 'DPMS Target SRG-APP-LOG'
  tag check_id: 'C-80831r1_chk'
  tag severity: 'low'
  tag gid: 'V-81167'
  tag rid: 'SV-95881r1_rule'
  tag stig_id: 'SRG-APP-000369-AU-000250'
  tag gtitle: 'SRG-APP-000369-AU-000250'
  tag fix_id: 'F-87943r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001881']
  tag nist: ['AU-7 b']
end
