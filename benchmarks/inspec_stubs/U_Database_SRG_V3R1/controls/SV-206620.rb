control 'SV-206620' do
  title 'The DBMS must generate audit records when security objects are modified.'
  desc 'Changes in the database objects (tables, views, procedures, functions) that record and control permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized changes to the security subsystem could go undetected. The database could be severely compromised or rendered inoperative.'
  desc 'check', 'If the DBMS architecture makes it impossible for any user, even with the highest privileges, to modify the structure and logic of its built-in security objects, and if there are no additional, locally-defined security objects in the database(s), this is not a finding.

Review DBMS documentation to verify that audit records can be produced when security objects are modified.

If the DBMS is not capable of this, this is a finding.

Review the DBMS/database security and audit configurations to verify that audit records are produced when security objects are modified.

If they are not produced, this is a finding.'
  desc 'fix', 'Deploy a DBMS capable of producing the required audit records when security objects, such as tables, views, procedures, and functions, are modified.

Configure the DBMS to produce audit records when security objects, such as tables, views, procedures, and functions, are modified.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6880r291528_chk'
  tag severity: 'medium'
  tag gid: 'V-206620'
  tag rid: 'SV-206620r617447_rule'
  tag stig_id: 'SRG-APP-000496-DB-000334'
  tag gtitle: 'SRG-APP-000496'
  tag fix_id: 'F-6880r291529_fix'
  tag 'documentable'
  tag legacy: ['SV-72517', 'V-58087']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
