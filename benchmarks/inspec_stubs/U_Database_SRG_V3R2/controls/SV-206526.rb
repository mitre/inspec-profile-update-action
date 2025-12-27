control 'SV-206526' do
  title 'The DBMS must be able to generate audit records when unsuccessful attempts to retrieve privileges/permissions occur.'
  desc 'Under some circumstances, it may be useful to monitor who/what is reading privilege/permission/role information. Therefore, it must be possible to configure auditing to do this. DBMSs typically make such information available through views or functions.

This requirement addresses explicit requests for privilege/permission/role membership information. It does not refer to the implicit retrieval of privileges/permissions/role memberships that the DBMS continually performs to determine if any and every action on the database is permitted.

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.'
  desc 'check', 'Review DBMS documentation to verify that audit records can be produced when the system denies or fails to complete attempts to retrieve privileges/permissions/role membership.

If the DBMS is not capable of this, this is a finding.

If the DBMS is currently required to audit the retrieval of privilege/permission/role membership information, review the DBMS/database security and audit configurations to verify that audit records are produced when the DBMS denies retrieval of privileges/permissions/role memberships.

If they are not produced, this is a finding.

Review the DBMS/database security and audit configurations to verify that audit records are produced when other errors prevent retrieval of privileges/permissions/role memberships.

If they are not produced, this is a finding.'
  desc 'fix', 'Deploy a DBMS capable of producing the required audit records when it denies or fails to complete access to privileges/permissions/role membership.

If currently required, configure the DBMS to produce audit records when it denies access to privileges/permissions/role membership.

Configure the DBMS to produce audit records when other errors prevent access to privileges/permissions/role membership.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6786r291246_chk'
  tag severity: 'medium'
  tag gid: 'V-206526'
  tag rid: 'SV-206526r617447_rule'
  tag stig_id: 'SRG-APP-000091-DB-000325'
  tag gtitle: 'SRG-APP-000091'
  tag fix_id: 'F-6786r291247_fix'
  tag 'documentable'
  tag legacy: ['SV-72499', 'V-58069']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
