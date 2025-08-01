control 'SV-207461' do
  title 'The VMM that provides an audit reduction capability must not alter original content or time ordering of audit records.'
  desc 'If the audit reduction capability alters the content or time ordering of audit records, the integrity of the audit records is compromised, and the records are no longer usable for forensic analysis.

Audit reduction is a process that manipulates collected audit information and organizes such information in a summary format that is more meaningful to analysts. Time ordering refers to the chronological organization of records based on time stamps. The degree of time stamp precision can affect this.

This requirement is specific to VMMs providing audit reduction capabilities. The audit reduction capability can be met either natively or through the use of third-party tools.'
  desc 'check', 'Verify the VMM that provides an audit reduction capability does not alter original content or time ordering of audit records.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM that provides an audit reduction capability so that it does not alter original content or time ordering of audit records.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7718r365787_chk'
  tag severity: 'medium'
  tag gid: 'V-207461'
  tag rid: 'SV-207461r854632_rule'
  tag stig_id: 'SRG-OS-000353-VMM-001310'
  tag gtitle: 'SRG-OS-000353'
  tag fix_id: 'F-7718r365788_fix'
  tag 'documentable'
  tag legacy: ['V-57123', 'SV-71383']
  tag cci: ['CCI-001881']
  tag nist: ['AU-7 b']
end
