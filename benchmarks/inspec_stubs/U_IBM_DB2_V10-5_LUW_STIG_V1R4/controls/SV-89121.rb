control 'SV-89121' do
  title 'DB2 must produce audit records containing sufficient information to establish the outcome (success or failure) of the events.'
  desc 'Information system auditing capability is critical for accurate forensic analysis. Without information about the outcome of events, security personnel cannot make an accurate assessment as to whether an attack was successful or if changes were made to the security state of the system.

Event outcomes can include indicators of event success or failure and event-specific results (e.g., the security state of the information system after the event occurred). As such, they also provide a means to measure the impact of an event and help authorized personnel to determine the appropriate response.'
  desc 'check', "Run the following SQL statement to confirm that all audit policies are created with STATUS='B':
DB2> SELECT * FROM SYSCAT.AUDITPOLICIES

If any audit policy does not have the values for all the audit category columns set to 'B' (Both) and the value in the ERRORTYPE column set to 'A' (Audit), EXECUTEWITHDATA to 'Y' for Execute category audit policies, this is a finding."
  desc 'fix', %q(Drop and recreate the policy with STATUS set to ""Both"" or use ALTER POLICY to set the STATUS='B'.

To drop and recreate a policy use following statements:
DB2> DROP AUDIT POLICY <audit1>
DB2> CREATE AUDIT POLICY <audit1> 
          CATEGORIES < audit categories >  STATUS BOTH ERROR TYPE AUDIT

To alter the audit policy:
DB2> ALTER AUDIT POLICY <audit1> 
          CATEGORIES < audit categories >  STATUS BOTH ERROR TYPE AUDIT

Notes: Each audit record has an Event Status represented by a SQLCODE where Successful event > = 0 Failed event < 0. To generate a record for both success and failed events, all the audit policies should be created with STATUS 'BOTH'.

CREATE AUDIT POLICY information:
http://www-01.ibm.com/support/knowledgecenter/SSEPGG_10.5.0/com.ibm.db2.luw.sql.ref.doc/doc/r0050607.html?lang=en

ALTER AUDIT POLICY information:
http://www-01.ibm.com/support/knowledgecenter/SSEPGG_10.5.0/com.ibm.db2.luw.sql.ref.doc/doc/r0050608.html?cp=SSEPGG_10.5.0%2F2-12-7-7&lang=en")
  impact 0.5
  ref 'DPMS Target IBM DB2 LUW 10.5 for Linux'
  tag check_id: 'C-74373r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74447'
  tag rid: 'SV-89121r1_rule'
  tag stig_id: 'DB2X-00-001600'
  tag gtitle: 'SRG-APP-000099-DB-000043'
  tag fix_id: 'F-81047r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end
