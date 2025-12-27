control 'SV-206502' do
  title 'The Central Log Server must be configured to perform audit reduction that does not alter original content or time ordering of log records.'
  desc 'If the audit reduction capability alters the content or time ordering of log records, the integrity of the log records is compromised, and the records are no longer usable for forensic analysis. Time ordering refers to the chronological organization of records based on time stamps. The degree of time stamp precision can affect this.

Audit reduction is a process that manipulates collected audit information and organizes such information in a summary format that is more meaningful to analysts.

This requirement is specific to applications with audit reduction capabilities; however, applications need to support on-demand audit review and analysis.'
  desc 'check', 'Examine the configuration.

Verify the Central Log Server performs audit reduction that does not alter original content or time ordering of log records.

If the Central Log Server is not configured to perform audit reduction that does not alter original content or time ordering of log records, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to perform audit reduction that does not alter original content or time ordering of log records.'
  impact 0.3
  ref 'DPMS Target Central Log Server'
  tag check_id: 'C-6762r285747_chk'
  tag severity: 'low'
  tag gid: 'V-206502'
  tag rid: 'SV-206502r855309_rule'
  tag stig_id: 'SRG-APP-000369-AU-000250'
  tag gtitle: 'SRG-APP-000369'
  tag fix_id: 'F-6762r285748_fix'
  tag 'documentable'
  tag legacy: ['SV-95881', 'V-81167']
  tag cci: ['CCI-001881']
  tag nist: ['AU-7 b']
end
