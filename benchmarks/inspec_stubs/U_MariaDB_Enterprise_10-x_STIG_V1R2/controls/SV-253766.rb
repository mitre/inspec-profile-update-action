control 'SV-253766' do
  title 'MariaDB must generate audit records for all privileged activities or other system-level access.'
  desc 'Without tracking privileged activity, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

System documentation should include a definition of the functionality considered privileged.

A privileged function in this context is any operation that modifies the structure of the database, its built-in logic, or its security settings. This would include all Data Definition Language (DDL) statements and all security-related statements. In an SQL environment, it encompasses, but is not necessarily limited to:

CREATE
ALTER
DROP
GRANT
REVOKE

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
  desc 'check', "Review the security plan to obtain the definition of the database/DBMS functionality considered privileged in the context of the system in question. 

If audit logging covers at least all of the actions defined as privileged, this is not a finding, otherwise, this is a finding.

Review the MariaDB audit settings. 

Verify the MariaDB Enterprise Audit plugin is loaded and actively logging:

MariaDB> SHOW GLOBAL STATUS LIKE 'Server_audit_active';

If the MariaDB Enterprise Audit plugin is not active, this is a finding. 

Check what filters are in place by running the following as an administrative user: 

MariaDB> SELECT * FROM mysql.server_audit_filters;

Review the filters to verify TABLE and QUERY are included. If QUERY and TABLE are not included, this is a finding."
  desc 'fix', 'Edit the necessary filters to include the desired logging actions. Exact steps vary depending on desired logging. 

Example named audit filter assigned to specific user: 

MariaDB> INSERT INTO mysql.server_audit_users (host, user, filtername)
   VALUES ("%", "user1", "filter_example");

MariaDB> SET GLOBAL server_audit_reload_filters=ON;'
  impact 0.5
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57218r841821_chk'
  tag severity: 'medium'
  tag gid: 'V-253766'
  tag rid: 'SV-253766r841823_rule'
  tag stig_id: 'MADB-10-011400'
  tag gtitle: 'SRG-APP-000504-DB-000354'
  tag fix_id: 'F-57169r841822_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
