control 'SV-89261' do
  title 'DB2 must generate audit records when unsuccessful attempts to execute privileged activities or other system-level access occur.'
  desc 'Without tracking privileged activity, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

System documentation should include a definition of the functionality considered privileged.

A privileged function in this context is any operation that modifies the structure of the database, its built-in logic, or its security settings. This would include all Data Definition Language (DDL) statements and all security-related statements. In an SQL environment, it encompasses, but is not necessarily limited to:

CREATE
ALTER
DROP
GRANT
REVOKE

Note that it is particularly important to audit, and tightly control, any action that weakens the implementation of this requirement itself, since the objective is to have a complete audit trail of all administrative activity.

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.'
  desc 'check', "Run the following SQL statement to ensure that an audit policy is defined upon the database: 
DB2> SELECT AUDITPOLICYNAME, AUDITPOLICYID 
           FROM SYSCAT.AUDITUSE 
           WHERE OBJECTTYPE IN (' ') 

If no rows are returned, this is a finding. 

Using the AUDITPOLICYID from above query find the details of audit policy: 
DB2> SELECT AUDITPOLICYNAME, SECMAINTSTATUS, SYSADMINSTATUS, OBJMAINTSTATUS, AUDITSTATUS, CONTEXTSTATUS, ERRORTYPE 
            FROM SYSCAT.AUDITPOLICIES 
            WHERE AUDITPOLICYID = <audit policy ID>

If the values for SECMAINTSTATUS, OBJMAINTSTATUS, SYSADMINSTATUS, AUDITSTATUS and CONTEXTSTATUS are not 'B' (Both) or 'F' (Failure), or ERRORTYPE is not 'A' (Audit), this is a finding."
  desc 'fix', 'Define an audit policy with the needed subset using the CREATE AUDIT POLICY SQL statement: 
DB2> CREATE AUDIT POLICY <DB audit policy name> 
           CATEGORIES SECMAINT STATUS BOTH, OBJMAINT STATUS BOTH, AUDIT STATUS BOTH, SYSADMIN STATUS BOTH, CONTEXT STATUS BOTH 
           ERROR TYPE AUDIT

To modify an existing audit policy, replace "CREATE" with "ALTER" in the preceding statement.  Only the categories explicitly named in the statement will be affected.  In this case, the changes take effect immediately.

If CREATE was used above, apply the policy created above to the database: 
DB2> AUDIT DATABASE USING POLICY <DB audit policy name>'
  impact 0.5
  ref 'DPMS Target IBM DB2 LUW 10.5 for Linux'
  tag check_id: 'C-74473r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74587'
  tag rid: 'SV-89261r1_rule'
  tag stig_id: 'DB2X-00-011700'
  tag gtitle: 'SRG-APP-000504-DB-000355'
  tag fix_id: 'F-81187r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
