control 'SV-206616' do
  title 'The DBMS must generate audit records when privileges/permissions are added.'
  desc 'Changes in the permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized elevation or restriction of privileges could go undetected. Elevated privileges give users access to information and functionality that they should not have; restricted privileges wrongly deny access to authorized users.

In an SQL environment, adding permissions is typically done via the GRANT command, or, in the negative, the DENY command.'
  desc 'check', 'Review DBMS documentation to verify that audit records can be produced when privileges/permissions/role memberships are added.

If the DBMS is not capable of this, this is a finding.

Review the DBMS/database security and audit configurations to verify that audit records are produced when privileges/permissions/role memberships are added.

If they are not produced, this is a finding.'
  desc 'fix', 'Deploy a DBMS capable of producing the required audit records when privileges/permissions/role memberships are added.

Configure the DBMS to produce audit records when privileges/permissions/role memberships are added.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6876r291516_chk'
  tag severity: 'medium'
  tag gid: 'V-206616'
  tag rid: 'SV-206616r617447_rule'
  tag stig_id: 'SRG-APP-000495-DB-000326'
  tag gtitle: 'SRG-APP-000495'
  tag fix_id: 'F-6876r291517_fix'
  tag 'documentable'
  tag legacy: ['V-58071', 'SV-72501']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
