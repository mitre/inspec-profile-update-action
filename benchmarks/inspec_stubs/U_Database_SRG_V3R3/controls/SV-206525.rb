control 'SV-206525' do
  title 'The DBMS must be able to generate audit records when privileges/permissions are retrieved.'
  desc 'Under some circumstances, it may be useful to monitor who/what is reading privilege/permission/role information. Therefore, it must be possible to configure auditing to do this. DBMSs typically make such information available through views or functions.

This requirement addresses explicit requests for privilege/permission/role membership information. It does not refer to the implicit retrieval of privileges/permissions/role memberships that the DBMS continually performs to determine if any and every action on the database is permitted.'
  desc 'check', 'Review DBMS documentation to verify that audit records can be produced when privileges/permissions/role memberships are retrieved.

If the DBMS is not capable of this, this is a finding.

If the DBMS is currently required to audit the retrieval of privilege/permission/role membership information, review the DBMS/database security and audit configurations to verify that audit records are produced when privileges/permissions/role memberships are retrieved.

If they are not produced, this is a finding.'
  desc 'fix', 'Deploy a DBMS capable of producing the required audit records when privileges/permissions/role memberships are retrieved.

If currently required, configure the DBMS to produce audit records when privileges/permissions/role memberships are retrieved.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6785r291243_chk'
  tag severity: 'medium'
  tag gid: 'V-206525'
  tag rid: 'SV-206525r617447_rule'
  tag stig_id: 'SRG-APP-000091-DB-000066'
  tag gtitle: 'SRG-APP-000091'
  tag fix_id: 'F-6785r291244_fix'
  tag 'documentable'
  tag legacy: ['SV-42701', 'V-32364']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
