control 'SV-213752' do
  title 'DB2 must generate audit records when unsuccessful attempts to delete categorized information (e.g., classification levels/security levels) occur.'
  desc 'Changes in categorized information must be tracked. Without an audit trail, unauthorized access to protected data could go undetected.

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.

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

If the database audit policy has the values for the CONTEXTSTATUS and EXECUTESTATUS columns set to 'F' (Failure) or 'B' (Both) and the value in the ERRORTYPE column set to 'A' (Audit), this is not a finding. 

If the database policy does not exist or does not cover CONTEXTSTATUS and EXECUTESTATUS then check if the appropriate policies are defined for all the required tables. 

If any required application table audit policies do not have the values for the CONTEXTSTATUS and EXECUTESTATUS columns set to 'F' (Failure) or 'B' (Both) or the value in the ERRORTYPE column set to 'A' (Audit), then this is a finding."
  desc 'fix', 'Run the following command to define an audit policy with the needed subset using the CREATE AUDIT POLICY SQL statement: 
DB2> CREATE AUDIT POLICY <DB audit policy name> 
           CATEGORIES SECMAINT STATUS BOTH, CONTEXT STATUS BOTH 
           ERROR TYPE AUDIT

Run the following command to apply the policy created above to the database: 
DB2> AUDIT DATABASE USING POLICY <DB audit policy name>'
  impact 0.5
  ref 'DPMS Target IBM DB2 V10.5 LUW'
  tag check_id: 'C-14973r295305_chk'
  tag severity: 'medium'
  tag gid: 'V-213752'
  tag rid: 'SV-213752r879873_rule'
  tag stig_id: 'DB2X-00-011300'
  tag gtitle: 'SRG-APP-000502-DB-000349'
  tag fix_id: 'F-14971r295306_fix'
  tag 'documentable'
  tag legacy: ['SV-89327', 'V-74653']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
