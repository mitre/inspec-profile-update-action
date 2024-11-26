control 'SV-89109' do
  title 'DB2 must protect against a user falsely repudiating having performed organization-defined actions.'
  desc "Non-repudiation of actions taken is required in order to maintain data integrity. Examples of particular actions taken by individuals include creating information, sending a message, approving information (e.g., indicating concurrence or signing a contract), and receiving a message. 

Non-repudiation protects against later claims by a user of not having created, modified, or deleted a particular data item or collection of data in the database.

In designing a database, the organization must define the types of data and the user actions that must be protected from repudiation. The implementation must then include building audit features into the application data tables, and configuring the DBMS' audit tools to capture the necessary audit trail. Design and implementation also must ensure that applications pass individual user identification to the DBMS, even where the application connects to the DBMS with a standard, group account."
  desc 'check', "Run the following SQL statement to ensure that an audit policy is defined upon all the required application tables and/or the database:
DB2> SELECT AUDITPOLICYNAME, OBJECTSCHEMA, OBJECTNAME, OBJECTTYPE 
           FROM SYSCAT.AUDITUSE 
           WHERE OBJECTTYPE IN ('T',' ')

If no rows are returned, this is a finding. 

If a row with OBJECTTYPE of ' ' (Database; value is a blank) exists in the output, it is a database level policy. 

If a row with OBJECTTYPE of 'T' exists in the output, it is a table level policy. 

For each audit policy returned in the statement above, run the following SQL statement to confirm that the CONTEXT and EXECUTE categories are part of that policy: 
DB2> SELECT AUDITPOLICYNAME, CONTEXTSTATUS, EXECUTESTATUS, ERRORTYPE AS ERRORTYPE 
           FROM SYSCAT.AUDITPOLICIES

If the database audit policy has the values for the CONTEXTSTATUS and EXECUTESTATUS columns set to 'S' (Success) or 'B' (Both) as well as the value in the ERRORTYPE column set to 'A' (Audit), this is not a finding. 

If the database policy does not exist or does not cover CONTEXTSTATUS or EXECUTESTATUS then check if the appropriate policies are defined for all the required application tables. 

If all the required application table audit policies do not have the values for the CONTEXTSTATUS and EXECUTESTATUS columns set to 'S' (Success) or 'B' (Both) as well as the value in the ERRORTYPE column set to 'A' (Audit), this is a finding."
  desc 'fix', 'Define the audit policy using the following Create Audit Policy SQL statement:
DB2> CREATE AUDIT POLICY <audit policy name> 
                CATEGORIES CONTEXT STATUS BOTH, EXECUTE STATUS BOTH
                ERROR TYPE AUDIT

Apply such a policy to either the database as a whole or to the specific application tables using one of these two statements: 
DB2> AUDIT DATABASE USING POLICY <audit policy name> 
 Or 
DB2> AUDIT TABLE <table name> USING POLICY <audit policy name> 

Note : While DB2 does provide basic audit capabilities, IBM highly recommends investing in and using a dedicated enterprise audit tool such as the IBM Security Guardium Data Activity Monitor in order to provide a comprehensive audit solution.'
  impact 0.5
  ref 'DPMS Target IBM DB2 LUW 10.5 for Linux'
  tag check_id: 'C-74361r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74435'
  tag rid: 'SV-89109r1_rule'
  tag stig_id: 'DB2X-00-000500'
  tag gtitle: 'SRG-APP-000080-DB-000063'
  tag fix_id: 'F-81035r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000166']
  tag nist: ['AU-10']
end
