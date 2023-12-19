control 'SV-206632' do
  title 'The DBMS must generate audit records for all privileged activities or other system-level access.'
  desc 'Without tracking privileged activity, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

System documentation should include a definition of the functionality considered privileged.

A privileged function in this context is any operation that modifies the structure of the database, its built-in logic, or its security settings. This would include all Data Definition Language (DDL) statements and all security-related statements. In an SQL environment, it encompasses, but is not necessarily limited to:
CREATE
ALTER
DROP
GRANT
REVOKE
DENY

There may also be Data Manipulation Language (DML) statements that, subject to context, should be regarded as privileged. Possible examples in SQL include:

TRUNCATE TABLE;
DELETE, or
DELETE affecting more than n rows, for some n, or
DELETE without a WHERE clause;

UPDATE or
UPDATE affecting more than n rows, for some n, or
UPDATE without a WHERE clause;

any SELECT, INSERT, UPDATE, or DELETE to an application-defined security table executed by other than a security principal.

Depending on the capabilities of the DBMS and the design of the database and associated applications, audit logging may be achieved by means of DBMS auditing features, database triggers, other mechanisms, or a combination of these.

Note that it is particularly important to audit, and tightly control, any action that weakens the implementation of this requirement itself, since the objective is to have a complete audit trail of all administrative activity.'
  desc 'check', 'Review DBMS documentation to verify that authorized administrative users can designate actions as privileged and that audit records can be produced when privileged actions occur.

If the DBMS is not capable of this, this is a finding.

Review the system documentation to obtain the definition of the database/DBMS functionality considered privileged in the context of the system in question. 

Review the DBMS/database security and audit configurations and/or other means used to implement audit logging.

If audit logging covers at least all of the actions defined as privileged, this is not a finding; otherwise, this is a finding.'
  desc 'fix', 'Deploy a DBMS capable of producing the required audit records when privileged actions occur.

Configure the DBMS to produce audit records when privileged actions occur.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6892r291564_chk'
  tag severity: 'medium'
  tag gid: 'V-206632'
  tag rid: 'SV-206632r617447_rule'
  tag stig_id: 'SRG-APP-000504-DB-000354'
  tag gtitle: 'SRG-APP-000504'
  tag fix_id: 'F-6892r291565_fix'
  tag 'documentable'
  tag legacy: ['SV-72545', 'V-58115']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
