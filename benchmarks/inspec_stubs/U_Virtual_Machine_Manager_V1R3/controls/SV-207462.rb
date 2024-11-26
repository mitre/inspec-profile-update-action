control 'SV-207462' do
  title 'The VMM that provides a report generation capability must not alter original content or time ordering of audit records.'
  desc 'If the report generation capability alters the content or time ordering of audit records, the integrity of the audit records is compromised, and the records are no longer usable for forensic analysis.

Time ordering refers to the chronological organization of records based on time stamps. The degree of time stamp precision can affect this.

This requirement is specific to VMMs providing report generation capabilities. The report generation capability can be met either natively or through the use of third-party tools.'
  desc 'check', 'Verify the VMM that provides a report generation capability does not alter original content or time ordering of audit records.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM that provides a report generation capability so that it does not alter original content or time ordering of audit records.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7719r365790_chk'
  tag severity: 'medium'
  tag gid: 'V-207462'
  tag rid: 'SV-207462r854633_rule'
  tag stig_id: 'SRG-OS-000354-VMM-001320'
  tag gtitle: 'SRG-OS-000354'
  tag fix_id: 'F-7719r365791_fix'
  tag 'documentable'
  tag legacy: ['SV-71385', 'V-57125']
  tag cci: ['CCI-001882']
  tag nist: ['AU-7 b']
end
