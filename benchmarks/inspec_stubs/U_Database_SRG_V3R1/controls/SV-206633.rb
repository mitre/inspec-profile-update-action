control 'SV-206633' do
  title 'The DBMS must generate audit records when unsuccessful attempts to execute privileged activities or other system-level access occur.'
  desc 'Without tracking privileged activity, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

System documentation should include a definition of the functionality considered privileged.

A privileged function in this context is any operation that modifies the structure of the database, its built-in logic, or its security settings. This would include all Data Definition Language (DDL) statements and all security-related statements. In an SQL environment, it encompasses, but is not necessarily limited to:
CREATE
ALTER
DROP
GRANT
REVOKE
DENY

Note that it is particularly important to audit, and tightly control, any action that weakens the implementation of this requirement itself, since the objective is to have a complete audit trail of all administrative activity.

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.'
  desc 'check', 'Review DBMS documentation to verify that authorized administrative users can designate actions as privileged and that audit records can be produced when the DBMS prevents attempted privileged actions.

If the DBMS is not capable of this, this is a finding.

Review the DBMS/database security and audit configurations to verify that audit records are produced when the DBMS prevents attempted privileged actions.

If they are not produced, this is a finding.'
  desc 'fix', 'Deploy a DBMS capable of producing the required audit records when the DBMS prevents attempted privileged action.

Configure the DBMS to produce audit records when the DBMS prevents attempted privileged actions.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6893r291567_chk'
  tag severity: 'medium'
  tag gid: 'V-206633'
  tag rid: 'SV-206633r617447_rule'
  tag stig_id: 'SRG-APP-000504-DB-000355'
  tag gtitle: 'SRG-APP-000504'
  tag fix_id: 'F-6893r291568_fix'
  tag 'documentable'
  tag legacy: ['SV-72547', 'V-58117']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
