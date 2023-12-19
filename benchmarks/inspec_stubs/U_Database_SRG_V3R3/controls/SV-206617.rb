control 'SV-206617' do
  title 'The DBMS must generate audit records when unsuccessful attempts to add privileges/permissions occur.'
  desc 'Failed attempts to change the permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized attempts to elevate or restrict privileges could go undetected. 

In an SQL environment, adding permissions is typically done via the GRANT command, or, in the negative, the DENY command. 

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.'
  desc 'check', 'Review DBMS documentation to verify that audit records can be produced when the system denies or fails to complete attempts to add privileges/permissions/role membership.

If the DBMS is not capable of this, this is a finding.

Review the DBMS/database security and audit configurations to verify that audit records are produced when the DBMS denies the addition of privileges/permissions/role membership.

If they are not produced, this is a finding.

Review the DBMS/database security and audit configurations to verify that audit records are produced when other errors prevent the addition of privileges/permissions/role membership.

If they are not produced, this is a finding.'
  desc 'fix', 'Deploy a DBMS capable of producing the required audit records when it denies or fails to complete attempts to add privileges/permissions/role membership.

Configure the DBMS to produce audit records when it denies attempts to add privileges/permissions/role membership.

Configure the DBMS to produce audit records when other errors prevent attempts to add privileges/permissions/role membership.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6877r291519_chk'
  tag severity: 'medium'
  tag gid: 'V-206617'
  tag rid: 'SV-206617r617447_rule'
  tag stig_id: 'SRG-APP-000495-DB-000327'
  tag gtitle: 'SRG-APP-000495'
  tag fix_id: 'F-6877r291520_fix'
  tag 'documentable'
  tag legacy: ['SV-72503', 'V-58073']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
