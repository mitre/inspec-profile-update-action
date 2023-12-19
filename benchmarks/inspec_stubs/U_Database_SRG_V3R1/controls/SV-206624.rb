control 'SV-206624' do
  title 'The DBMS must generate audit records when privileges/permissions are deleted.'
  desc 'Changes in the permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized elevation or restriction of privileges could go undetected. Elevated privileges give users access to information and functionality that they should not have; restricted privileges wrongly deny access to authorized users.

In an SQL environment, deleting permissions is typically done via the REVOKE or DENY command.'
  desc 'check', 'Review DBMS documentation to verify that audit records can be produced when privileges/permissions/role memberships are removed, revoked, or denied to any user or role.

If the DBMS is not capable of this, this is a finding.

Review the DBMS/database security and audit configurations to verify that audit records are produced when privileges/permissions/role memberships are removed, revoked, or denied to any user or role.

If they are not produced, this is a finding.'
  desc 'fix', 'Deploy a DBMS capable of producing the required audit records when privileges/permissions/role memberships are removed, revoked, or denied to any user or role.

Configure DBMS audit settings to generate an audit record when privileges/permissions/role memberships are removed, revoked, or denied to any user or role.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6884r291540_chk'
  tag severity: 'medium'
  tag gid: 'V-206624'
  tag rid: 'SV-206624r617447_rule'
  tag stig_id: 'SRG-APP-000499-DB-000330'
  tag gtitle: 'SRG-APP-000499'
  tag fix_id: 'F-6884r291541_fix'
  tag 'documentable'
  tag legacy: ['SV-72509', 'V-58079']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
