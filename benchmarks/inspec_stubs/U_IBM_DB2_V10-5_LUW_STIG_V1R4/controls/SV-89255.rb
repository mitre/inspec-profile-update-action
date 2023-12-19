control 'SV-89255' do
  title 'DB2 must generate audit records when successful accesses to objects occur.'
  desc 'Without tracking all or selected types of access to all or selected objects (tables, views, procedures, functions, etc.), it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one. 

In an SQL environment, types of access include, but are not necessarily limited to:

SELECT
INSERT
UPDATE
DELETE
EXECUTE'
  desc 'check', "Run the following SQL statement to ensure that an audit policy is defined upon the all required application tables, routines and/or the database: 
DB2> SELECT AUDITPOLICYNAME, OBJECTSCHEMA, OBJECTNAME, OBJECTTYPE 
           FROM SYSCAT.AUDITUSE 
           WHERE OBJECTTYPE IN ('T',' ')

If no rows are returned, this is a finding. 

If a row with OBJECTTYPE of ' ' (Database; value is a blank) exists in the output, it is a database level policy. 

If a row with OBJECTTYPE of 'T' exists in the output, it is a table level policy. 

For each audit policy returned in the statement above, run the following SQL statement to confirm that the CONTEXT and EXECUTE categories are part of that policy: 
DB2> SELECT AUDITPOLICYNAME, CONTEXTSTATUS, EXECUTESTATUS, ERRORTYPE AS ERRORTYPE 
           FROM SYSCAT.AUDITPOLICIES

If the database audit policy has the values for the CONTEXTSTATUS and EXECUTESTATUS columns set to 'S' (Success) or 'B' (Both) and the value in the ERRORTYPE column set to 'A' (Audit), this is not a finding.

If the database policy does not exist or does not cover CONTEXTSTATUS or EXECUTESTATUS then check if the appropriate policies are defined for all the required application tables. 

If any required application table audit policies do not have the values for the CONTEXTSTATUS and EXECUTESTATUS columns set to 'S' (Success) or 'B' (Both) or the value in the ERRORTYPE column set to 'A' (Audit), then this is a finding.

Note: If the routines (stored procedures) execution need to be audited then execute policy has to be defined at database level. In DB2 EXECUTE policy can be created at the Database level or table level. EXECUTE audit policy covers the routine also if defined at database level.  Currently there is no provision to define auditing of individual/specified routines."
  desc 'fix', 'Run the following command to define an audit policy with the needed subset using the CREATE AUDIT POLICY SQL statement: 
DB2> CREATE AUDIT POLICY <execdb> 
           CATEGORIES CONTEXT STATUS BOTH, EXECUTE STATUS BOTH 
           ERROR TYPE AUDIT

To modify an existing audit policy, replace "CREATE" with "ALTER" in the preceding statement. Only the categories explicitly named in the statement will be affected.  In this case, the changes take effect immediately.

If CREATE was used above, run one of the following commands to apply the correct policy to either the database as a whole or to the specific application tables: 
DB2> AUDIT DATABASE USING POLICY EXECDB
  Or 
DB2> AUDIT TABLE <table name> USING POLICY EXECDB'
  impact 0.5
  ref 'DPMS Target IBM DB2 LUW 10.5 for Linux'
  tag check_id: 'C-74467r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74581'
  tag rid: 'SV-89255r1_rule'
  tag stig_id: 'DB2X-00-012000'
  tag gtitle: 'SRG-APP-000507-DB-000356'
  tag fix_id: 'F-81181r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
