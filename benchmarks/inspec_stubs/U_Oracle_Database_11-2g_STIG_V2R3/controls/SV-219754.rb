control 'SV-219754' do
  title 'The DBMS must produce audit records containing sufficient information to establish what type of events occurred.'
  desc "Information system auditing capability is critical for accurate forensic analysis. Audit record content that may be necessary to satisfy the requirement of this control includes:  timestamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, file names involved, and access control or flow control rules invoked. 

Database software is capable of a range of actions on data stored within the database. It's important, for accurate forensic analysis, to know exactly what actions were performed. This requires specific information regarding the event type an audit record is referring to. If event type information is not recorded and stored with the audit record, the record itself is of very limited use."
  desc 'check', %q(Verify, using vendor and system documentation if necessary, that the DBMS is configured to use Oracle's auditing features, or that a third-party product or custom code is deployed and configured to satisfy this requirement.

If a third-party product or custom code is used, compare its current configuration with the audit requirements. If any of the requirements is not covered by the configuration, this is a finding.

The remainder of this Check is applicable specifically where Oracle auditing is in use.

To see if Oracle is configured to capture audit data, enter the following SQLPlus command:
SHOW PARAMETER AUDIT_TRAIL
or the following SQL query:
SELECT * FROM SYS.V$PARAMETER WHERE NAME = 'audit_trail';
If Oracle returns the value "NONE", this is a finding.

To confirm that Oracle audit is capturing sufficient information to establish the identity of the user/subject or process, perform a successful auditable action and an auditable action that results in an SQL error, and then view the results in the SYS.AUD$ table or the audit file, whichever is in use.  If no ACTION#, or the wrong value, is returned for the auditable actions just performed, this is a finding.)
  desc 'fix', "Configure the DBMS's auditing to audit standard and organization-defined auditable events, the audit record to include what type of event occurred. If preferred, use a third-party or custom tool. 

If using a third-party product, proceed in accordance with the product documentation. If using Oracle's capabilities, proceed as follows.

Use this query to ensure auditable events are captured:
ALTER SYSTEM SET AUDIT_TRAIL=<audit trail type> SCOPE=SPFILE;
Audit trail type can be 'OS', 'DB', 'DB,EXTENDED', 'XML' or 'XML,EXTENDED'.
After executing this statement, it may be necessary to shut down and restart the Oracle database.

For more information on the configuration of auditing, please refer to 'Auditing Database Activity' in the Oracle Database 2 Day + Security Guide:
http://docs.oracle.com/cd/E11882_01/server.112/e10575/tdpsg_auditing.htm
and 'Verifying Security Access with Auditing' in the Oracle Database Security Guide: http://docs.oracle.com/cd/E11882_01/network.112/e36292/auditing.htm#DBSEG006
and '27 DBMS_AUDIT_MGMT' in the Oracle Database PL/SQL Packages and Types Reference:
http://docs.oracle.com/cd/E11882_01/appdev.112/e40758/d_audit_mgmt.htm"
  impact 0.5
  ref 'DPMS Target Oracle Database 11.2g'
  tag check_id: 'C-21479r307111_chk'
  tag severity: 'medium'
  tag gid: 'V-219754'
  tag rid: 'SV-219754r395721_rule'
  tag stig_id: 'O112-C2-007400'
  tag gtitle: 'SRG-APP-000095-DB-000039'
  tag fix_id: 'F-21478r307112_fix'
  tag 'documentable'
  tag legacy: ['SV-66687', 'V-52471']
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
