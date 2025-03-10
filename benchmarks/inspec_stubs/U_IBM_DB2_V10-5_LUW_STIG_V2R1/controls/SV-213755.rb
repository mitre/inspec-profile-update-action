control 'SV-213755' do
  title 'DB2 must generate audit records for all privileged activities or other system-level access.'
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
  desc 'check', "Run the following SQL statement to ensure that an audit policy is defined upon the database: 
DB2> SELECT AUDITPOLICYNAME, AUDITPOLICYID 
           FROM SYSCAT.AUDITUSE 
           WHERE OBJECTTYPE IN (' ') 

If no rows are returned, this is a finding. 

Using the AUDITPOLICYID from above query find the details of the audit policy: 
DB2> SELECT AUDITPOLICYNAME, SECMAINTSTATUS, SYSADMINSTATUS, OBJMAINTSTATUS, AUDITSTATUS, CONTEXTSTATUS, ERRORTYPE 
           FROM SYSCAT.AUDITPOLICIES 
           WHERE AUDITPOLICYID = <audit policy ID>

If the values for SECMAINTSTATUS, OBJMAINTSTATUS, SYSADMINSTATUS, AUDITSTATUS and CONTEXTSTATUS are not 'B' (Both) or ERRORTYPE is not 'A' (Audit), this is a finding."
  desc 'fix', 'Define an audit policy with the needed subset using the CREATE AUDIT POLICY SQL statement: 

DB2> CREATE AUDIT POLICY <DB audit policy name> 
           CATEGORIES SECMAINT STATUS BOTH, OBJMAINT STATUS BOTH, AUDIT STATUS BOTH, SYSADMIN STATUS BOTH, CONTEXT STATUS BOTH 
           ERROR TYPE AUDIT

To modify an existing audit policy, replace "CREATE" with "ALTER" in the preceding statement. Only the categories explicitly named in the statement will be affected.  In this case, the changes take effect immediately.

If CREATE was used above, apply the policy created to the database: 
DB2> AUDIT DATABASE USING POLICY <DB audit policy name>'
  impact 0.5
  ref 'DPMS Target IBM DB2 V10.5 LUW'
  tag check_id: 'C-14976r295314_chk'
  tag severity: 'medium'
  tag gid: 'V-213755'
  tag rid: 'SV-213755r879875_rule'
  tag stig_id: 'DB2X-00-011600'
  tag gtitle: 'SRG-APP-000504-DB-000354'
  tag fix_id: 'F-14974r295315_fix'
  tag 'documentable'
  tag legacy: ['SV-89317', 'V-74643']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
