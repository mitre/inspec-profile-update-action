control 'SV-220273' do
  title 'The DBMS must produce audit records containing sufficient information to establish the sources (origins) of the events.'
  desc 'Information system auditing capability is critical for accurate forensic analysis. Audit record content that may be necessary to satisfy the requirement of this control, includes, but is not limited to:  timestamps, source and destination IP addresses, user/process identifiers, event descriptions, application specific events, success/fail indications, file names involved, access control or flow control rules invoked.

Without information establishing the source of activity, the value of audit records from a forensics perspective is questionable.'
  desc 'check', %q(Verify, using vendor and system documentation if necessary, that the DBMS is configured to use Oracle's auditing features, or that a third-party product or custom code is deployed and configured to satisfy this requirement.

If a third-party product or custom code is used, compare its current configuration with the audit requirements. If any of the requirements is not covered by the configuration, this is a finding.

The remainder of this Check is applicable specifically where Oracle auditing is in use.

If Standard Auditing is used:
To see if Oracle is configured to capture audit data, enter the following SQL*Plus command:

SHOW PARAMETER AUDIT_TRAIL

or the following SQL query:

SELECT * FROM SYS.V$PARAMETER WHERE NAME = 'audit_trail';

If Oracle returns the value 'NONE', this is a finding.

To confirm that Oracle audit is capturing sufficient information to establish the source of events, perform a successful auditable action and an auditable action that results in an SQL error, and then view the results in the SYS.AUD$ table or the audit file, whichever is in use.

If correct values for User ID, User Host, and Terminal are not returned when applicable, this is a finding.

If Unified Auditing is used:
To see if Oracle is configured to capture audit data, enter the following SQL*Plus command:

SELECT * FROM V$OPTION WHERE PARAMETER = 'Unified Auditing';

If Oracle returns a value something other than "TRUE", this is a finding. 

To confirm that Oracle audit is capturing sufficient information to establish the source of events, perform a successful auditable action and an auditable action that results in an SQL error, and then view the results in the SYS.UNIFIED_AUDIT_TRAIL view.

If correct values for DBUSERNAME, USERHOST, and TERMINAL are not returned when applicable, this is a finding.)
  desc 'fix', %q(Configure the DBMS's auditing to audit standard and organization-defined auditable events, the audit record to include the source of the event. If preferred, use a third-party or custom tool.

If using a third-party product, proceed in accordance with the product documentation. If using Oracle's capabilities, proceed as follows.

If Standard Auditing is used:
Use this process to ensure auditable events are captured:

ALTER SYSTEM SET AUDIT_TRAIL=<audit trail type> SCOPE=SPFILE;

Audit trail type can be 'OS', 'DB', 'DB,EXTENDED', 'XML' or 'XML,EXTENDED'.
After executing this statement, it may be necessary to shut down and restart the Oracle database.

If Unified Auditing is used:
To ensure auditable events are captured:
Link the oracle binary with uniaud_on, and then restart the database.                                                                                                                                                                                  
Oracle Database Upgrade Guide describes how to enable unified auditing.

For more information on the configuration of auditing, refer to the following documents:
"Auditing Database Activity" in the Oracle Database 2 Day + Security Guide:
http://docs.oracle.com/database/121/TDPSG/tdpsg_auditing.htm#TDPSG50000
"Monitoring Database Activity with Auditing" in the Oracle Database Security Guide:
http://docs.oracle.com/database/121/DBSEG/part_6.htm#CCHEHCGI
"DBMS_AUDIT_MGMT" in the Oracle Database PL/SQL Packages and Types Reference:
http://docs.oracle.com/database/121/ARPLS/d_audit_mgmt.htm#ARPLS241
Oracle Database Upgrade Guide:
http://docs.oracle.com/database/121/UPGRD/afterup.htm#UPGRD52810)
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-21988r836895_chk'
  tag severity: 'medium'
  tag gid: 'V-220273'
  tag rid: 'SV-220273r836896_rule'
  tag stig_id: 'O121-C2-007700'
  tag gtitle: 'SRG-APP-000098-DB-000042'
  tag fix_id: 'F-21980r391951_fix'
  tag 'documentable'
  tag legacy: ['SV-76125', 'V-61635']
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end
