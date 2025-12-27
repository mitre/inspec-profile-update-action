control 'SV-213751' do
  title 'DB2 must generate audit records when categorized information (e.g., classification levels/security levels) is deleted.'
  desc 'Changes in categorized information must be tracked. Without an audit trail, unauthorized access to protected data could go undetected.

For detailed information on categorizing information, refer to FIPS Publication 199, Standards for Security Categorization of Federal Information and Information Systems, and FIPS Publication 200, Minimum Security Requirements for Federal Information and Information Systems.'
  desc 'check', "Get a list of tables from ISSO/DBA where the categorized information is stored. 

If there are no tables with categorized information, this is not applicable (NA).

Run the following SQL statement to ensure that an audit policy is defined upon all the required tables and/or the database:
DB2> SELECT AUDITPOLICYNAME, OBJECTSCHEMA, OBJECTNAME, OBJECTTYPE 
           FROM SYSCAT.AUDITUSE 
           WHERE OBJECTTYPE IN ('T',' ')

If no rows are returned, this is a finding. 

If a row with OBJECTTYPE of ' ' (Database; value is a blank) exists in the output, it is a database level policy. 

If a row with OBJECTTYPE of 'T' exists in the output, it is a table level policy. 

For each audit policy returned in the statement above, run the following SQL statement to confirm that the CONTEXT and EXECUTE categories are part of that policy: 
DB2> SELECT AUDITPOLICYNAME, CONTEXTSTATUS, EXECUTESTATUS, ERRORTYPE AS ERRORTYPE 
           FROM SYSCAT.AUDITPOLICIES
           WHERE AUDITPOLICYID = <audit policy ID>

If the database audit policy has the values for the CONTEXTSTATUS and EXECUTESTATUS columns set to 'S' (Success) or 'B' (Both) and the value in the ERRORTYPE column set to 'A' (Audit), this is not a finding. 

If the database policy does not exist or does not cover CONTEXTSTATUS and EXECUTESTATUS then check if the appropriate policies are defined for all the required tables. 

If any required application table audit policies do not have the values for the CONTEXTSTATUS and EXECUTESTATUS columns set to 'S' (Success) or 'B' (Both) or the value in the ERRORTYPE column set to 'A' (Audit), then this is a finding."
  desc 'fix', 'Define an audit policy with the needed subset using the CREATE AUDIT POLICY SQL statement: 
DB2> CREATE AUDIT POLICY <DB audit policy name> 
           CATEGORIES EXECUTE STATUS BOTH, CONTEXT STATUS BOTH 
           ERROR TYPE AUDIT

To modify an existing audit policy, replace "CREATE" with "ALTER" in the preceding statement.  Only the categories explicitly named in the statement will be affected.  In this case, the changes take effect immediately.

If CREATE was used above, run the following command to apply the policy created above to the database: 
DB2> AUDIT DATABASE USING POLICY <DB audit policy name>

Define an audit policy to audit deletes (DMLs) on required tables. 
DB2> CREATE AUDIT POLICY <table audit policy name> 
           CATEGORIES EXECUTE STATUS BOTH, CONTEXT STATUS BOTH 
           ERROR TYPE AUDIT

To modify an existing audit policy, replace "CREATE" with "ALTER" in the preceding statement.  Only the categories explicitly named in the statement will be affected. In this case, the changes take effect immediately.

If CREATE was used above, run the following command to apply the policy created above to each required table:
DB2> AUDIT TABLE <table name> USING POLICY <table audit policy name>'
  impact 0.5
  ref 'DPMS Target IBM DB2 V10.5 LUW'
  tag check_id: 'C-14972r295302_chk'
  tag severity: 'medium'
  tag gid: 'V-213751'
  tag rid: 'SV-213751r879873_rule'
  tag stig_id: 'DB2X-00-011200'
  tag gtitle: 'SRG-APP-000502-DB-000348'
  tag fix_id: 'F-14970r295303_fix'
  tag 'documentable'
  tag legacy: ['SV-89325', 'V-74651']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
