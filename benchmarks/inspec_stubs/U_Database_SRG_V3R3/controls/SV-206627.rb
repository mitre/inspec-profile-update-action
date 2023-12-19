control 'SV-206627' do
  title 'The DBMS must generate audit records when unsuccessful attempts to delete security objects occur.'
  desc "The removal of security objects from the database/DBMS would seriously degrade a system's information assurance posture. If such an action is attempted, it must be logged.

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones."
  desc 'check', 'If the DBMS architecture makes it impossible for any user, even with the highest privileges, to drop its built-in security objects, and if there are no additional, locally-defined security objects in the database(s), this is not a finding.

Review DBMS documentation to verify that audit records can be produced when the system denies or fails to complete attempts to drop security objects.

If the DBMS is not capable of this, this is a finding.

Review the DBMS/database security and audit configurations to verify that audit records are produced when the system denies attempts to drop security objects.

If they are not produced, this is a finding.

Review the DBMS/database security and audit configurations to verify that audit records are produced when other errors prevent attempts to drop security objects.

If they are not produced, this is a finding.'
  desc 'fix', 'Deploy a DBMS capable of producing the required audit records when it denies or fails to complete attempts to delete security objects.

Configure the DBMS to produce audit records when it denies attempts to delete security objects.

Configure the DBMS to produce audit records when other errors prevent attempts to delete security objects.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6887r291549_chk'
  tag severity: 'medium'
  tag gid: 'V-206627'
  tag rid: 'SV-206627r617447_rule'
  tag stig_id: 'SRG-APP-000501-DB-000337'
  tag gtitle: 'SRG-APP-000501'
  tag fix_id: 'F-6887r291550_fix'
  tag 'documentable'
  tag legacy: ['SV-72523', 'V-58093']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
