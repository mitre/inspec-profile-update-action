control 'SV-206621' do
  title 'The DBMS must generate audit records when unsuccessful attempts to modify security objects occur.'
  desc 'Changes in the database objects (tables, views, procedures, functions) that record and control permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized changes to the security subsystem could go undetected. The database could be severely compromised or rendered inoperative.

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.'
  desc 'check', 'If the DBMS architecture makes it impossible for any user, even with the highest privileges, to modify the structure and logic of its built-in security objects, and if there are no additional, locally-defined security objects in the database(s), this is not a finding.

Review DBMS documentation to verify that audit records can be produced when the system denies or fails to complete attempts to modify security objects.

If the DBMS is not capable of this, this is a finding.

Review the DBMS/database security and audit configurations to verify that audit records are produced when the system denies attempts to modify security objects.

If they are not produced, this is a finding.

Review the DBMS/database security and audit configurations to verify that audit records are produced when other errors prevent attempts to modify security objects.

If they are not produced, this is a finding.'
  desc 'fix', 'Deploy a DBMS capable of producing the required audit records when it denies or fails to complete attempts to modify security objects, such as tables, views, procedures, and functions.

Configure the DBMS to produce audit records when it denies attempts to modify security objects, to include reads, creations, modifications, and deletions.

Configure the DBMS to produce audit records when other errors prevent attempts to modify security objects, to include reads, creations, modifications, and deletions.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6881r291531_chk'
  tag severity: 'medium'
  tag gid: 'V-206621'
  tag rid: 'SV-206621r617447_rule'
  tag stig_id: 'SRG-APP-000496-DB-000335'
  tag gtitle: 'SRG-APP-000496'
  tag fix_id: 'F-6881r291532_fix'
  tag 'documentable'
  tag legacy: ['SV-72519', 'V-58089']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
