control 'SV-203709' do
  title 'The operating system must not alter original content or time ordering of audit records when it provides an audit reduction capability.'
  desc 'If the audit reduction capability alters the content or time ordering of audit records, the integrity of the audit records is compromised, and the records are no longer usable for forensic analysis.

Audit reduction is a process that manipulates collected audit information and organizes such information in a summary format that is more meaningful to analysts. Time ordering refers to the chronological organization of records based on time stamps. The degree of time stamp precision can affect this.

This requirement is specific to operating systems providing audit reduction capabilities. The audit reduction capability can be met either natively or through the use of third-party tools.'
  desc 'check', 'Verify the operating system does not alter original content or time ordering of audit records when it provides an audit reduction capability. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to not alter original content or time ordering of audit records when it provides an audit reduction capability.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3834r375074_chk'
  tag severity: 'medium'
  tag gid: 'V-203709'
  tag rid: 'SV-203709r379726_rule'
  tag stig_id: 'SRG-OS-000353-GPOS-00141'
  tag gtitle: 'SRG-OS-000353'
  tag fix_id: 'F-3834r375075_fix'
  tag 'documentable'
  tag legacy: ['V-57263', 'SV-71523']
  tag cci: ['CCI-001881']
  tag nist: ['AU-7 b']
end
