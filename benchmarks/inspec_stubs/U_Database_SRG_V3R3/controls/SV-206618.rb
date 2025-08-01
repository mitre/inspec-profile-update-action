control 'SV-206618' do
  title 'The DBMS must generate audit records when privileges/permissions are modified.'
  desc 'Changes in the permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized elevation or restriction of privileges could go undetected. Elevated privileges give users access to information and functionality that they should not have; restricted privileges wrongly deny access to authorized users.

In an SQL environment, modifying permissions is typically done via the GRANT, REVOKE, and DENY commands.'
  desc 'check', "If there is no distinction in the DBMS's security architecture between modifying permissions on the one hand, and adding and deleting permissions on the other hand, this is not a finding.

Review DBMS documentation to verify that audit records can be produced when privileges/permissions/role memberships are modified.

If the DBMS is not capable of this, this is a finding.

Review the DBMS/database security and audit configurations to verify that audit records are produced when privileges/permissions/role memberships are modified.

If they are not produced, this is a finding."
  desc 'fix', 'Deploy a DBMS capable of producing the required audit records when privileges/permissions/role memberships are modified.

Configure the DBMS to produce audit records when privileges/permissions/role memberships are modified.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6878r291522_chk'
  tag severity: 'medium'
  tag gid: 'V-206618'
  tag rid: 'SV-206618r617447_rule'
  tag stig_id: 'SRG-APP-000495-DB-000328'
  tag gtitle: 'SRG-APP-000495'
  tag fix_id: 'F-6878r291523_fix'
  tag 'documentable'
  tag legacy: ['SV-72505', 'V-58075']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
