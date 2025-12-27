control 'SV-89247' do
  title 'DB2 must provide an immediate real-time alert to appropriate support staff of all audit failure events requiring real-time alerts.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability, and system operation may be adversely affected. 

The appropriate support staff include, at a minimum, the ISSO and the DBA/SA.

Alerts provide organizations with urgent messages. Real-time alerts provide these messages immediately (i.e., the time from event detection to alert occurs in seconds or less).'
  desc 'check', %q(If the audit policies are created with ERRORTYPE=Audit and if there is a failure in writing the audit event log for the policy, audit failure is logged in the diagnostic.log file and user action is not completed. 

Run the following statement to find the error type for each policy:
DB2> SELECT AUDITPOLICYNAME, ERRORTYPE AS ERRORTYPE 
FROM SYSCAT.AUDITPOLICIES

If ERRORTYPE value is not set to 'A', this is a finding. 

Run the following command to monitor the database diagnostic log file for audit failure errors:

     $db2diag -g msg:="Write to audit log failed"

If the diagnostic log file is not being monitored for audit failure errors, this is a finding.)
  desc 'fix', 'Run the following command to alter the audit policies and to set the ERRORTYPE to audit: 
DB2>ALTER AUDIT POLICY <DB audit policy name> CATEGORIES AUDIT STATUS BOTH  ERROR TYPE AUDIT

Monitor the diagnostic log file for audit failure error using the following command: 

     $db2diag  -g msg:="Write to audit log failed"'
  impact 0.5
  ref 'DPMS Target IBM DB2 LUW 10.5 for Linux'
  tag check_id: 'C-74459r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74573'
  tag rid: 'SV-89247r1_rule'
  tag stig_id: 'DB2X-00-007700'
  tag gtitle: 'SRG-APP-000360-DB-000320'
  tag fix_id: 'F-81173r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
