control 'SV-203710' do
  title 'The operating system must not alter original content or time ordering of audit records when it provides a report generation capability.'
  desc 'If the report generation capability alters the content or time ordering of audit records, the integrity of the audit records is compromised, and the records are no longer usable for forensic analysis.

Time ordering refers to the chronological organization of records based on time stamps. The degree of time stamp precision can affect this.

This requirement is specific to operating systems providing report generation capabilities. The report generation capability can be met either natively or through the use of third-party tools.'
  desc 'check', 'Verify the operating system does not alter original content or time ordering of audit records when it provides a report generation capability. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to not alter original content or time ordering of audit records when it provides a report generation capability.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3835r375077_chk'
  tag severity: 'medium'
  tag gid: 'V-203710'
  tag rid: 'SV-203710r851777_rule'
  tag stig_id: 'SRG-OS-000354-GPOS-00142'
  tag gtitle: 'SRG-OS-000354'
  tag fix_id: 'F-3835r375078_fix'
  tag 'documentable'
  tag legacy: ['SV-71525', 'V-57265']
  tag cci: ['CCI-001882']
  tag nist: ['AU-7 b']
end
