control 'SV-220313' do
  title 'The DBMS must protect against an individual who uses a shared account falsely denying having performed a particular action.'
  desc 'Non-repudiation of actions taken is required in order to maintain application integrity. Examples of particular actions taken by individuals include creating information, sending a message, approving information (e.g., indicating concurrence or signing a contract), and receiving a message.

Non-repudiation protects individuals against later claims by an author of not having authored a particular document, a sender of not having transmitted a message, a receiver of not having received a message, or a signatory of not having signed a document. 

Authentication via shared accounts does not provide individual accountability for actions taken on the DBMS or data. Whenever a single database account is used to connect to the database, a secondary authentication method that provides individual accountability is required. This scenario most frequently occurs when an externally hosted application authenticates individual users to the application and the application uses a single account to retrieve or update database information on behalf of the individual users.

When shared accounts are utilized without another means of identifying individual users, users may deny having performed a particular action.

This calls for inspection of application source code, which will require collaboration with the application developers. It is recognized that in many cases, the database administrator (DBA) is organizationally separate from the application developers and may have limited, if any, access to source code. Nevertheless, protections of this type are so important to the secure operation of databases that they must not be ignored. At a minimum, the DBA must attempt to obtain assurances from the development organization that this issue has been addressed and must document what has been discovered.'
  desc 'check', %q(If there are no shared accounts available to more than one user, this is not a finding.

If a shared account is used by an application to interact with the database, review the System Security Plan, the tables in the database, and the application source code/documentation to determine whether the application captures the individual user's identity and stores that identity along with all data inserted and updated (also with all records of reads and/or deletions, if these are required to be logged).

If there are gaps in the application's ability to do this, and the gaps and the risk are not defined in the system documentation and accepted by the AO, this is a finding.

If users are sharing a group account to log on to Oracle tools or third-party products that access the database, this is a finding.

If Standard Auditing is used:
To ensure that user activities other than SELECT, INSERT, UPDATE, and DELETE are also monitored and attributed to individuals, verify that Oracle auditing is enabled. To see if Oracle is configured to capture audit data, enter the following SQL*Plus command:
SHOW PARAMETER AUDIT_TRAIL
or the following SQL query:
SELECT * FROM SYS.V$PARAMETER WHERE NAME = 'audit_trail';
If Oracle returns the value 'NONE', this is a finding.

If Unified Auditing is used:
To ensure that user activities other than SELECT, INSERT, UPDATE, and DELETE are also monitored and attributed to individuals, verify that Oracle auditing is enabled. To see if Oracle is configured to capture audit data, enter the following SQL*Plus command:
SELECT * FROM V$OPTION WHERE PARAMETER = 'Unified Auditing';
If Oracle returns the value "TRUE", this is not a finding.)
  desc 'fix', %q(Use accounts assigned to individual users where feasible. Configure DBMS to provide individual accountability at the DBMS level, and in audit logs, for actions performed under a shared database account.

Modify applications and data tables that are not capturing individual user identity to do so.

Create and enforce the use of individual user IDs for logging on to Oracle tools and third-party products.

If Oracle auditing is not already enabled, enable it.

If Standard Auditing is used:
If Oracle (or third-party) auditing is not already enabled, enable it. For Oracle auditing, use this query:
ALTER SYSTEM SET AUDIT_TRAIL=<audit trail type> SCOPE=SPFILE;
Audit trail type can be 'OS', 'DB', 'DB,EXTENDED', 'XML' or 'XML,EXTENDED'.
After executing this statement, it may be necessary to shut down and restart the Oracle database.

If Unified Auditing is used:
Link the oracle binary with uniaud_on, and then restart the database. Oracle Database Upgrade Guide describes how to enable unified auditing.

For more information on the configuration of auditing, refer to the following documents:
"Auditing Database Activity" in the Oracle Database 2 Day + Security Guide:
http://docs.oracle.com/database/121/TDPSG/tdpsg_auditing.htm#TDPSG50000
"Monitoring Database Activity with Auditing" in the Oracle Database Security Guide: 
http://docs.oracle.com/database/121/DBSEG/part_6.htm#CCHEHCGI
"DBMS_AUDIT_MGMT" in the Oracle Database PL/SQL Packages and Types Reference:
http://docs.oracle.com/database/121/ARPLS/d_audit_mgmt.htm#ARPLS241
Oracle Database Upgrade Guide:
http://docs.oracle.com/database/121/UPGRD/afterup.htm#UPGRD52810

If the site-specific audit requirements are not covered by the default audit options, deploy and configure Fine-Grained Auditing.  For details, refer to Oracle documentation at the locations above.

If this level of auditing does not meet site-specific requirements, consider deploying the Oracle Audit Vault.  The Audit Vault is a highly configurable option from Oracle made specifically for performing the audit functions.  It has reporting capabilities as well as user-defined rules that provide additional flexibility for complex auditing requirements.)
  impact 0.3
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-22028r392070_chk'
  tag severity: 'low'
  tag gid: 'V-220313'
  tag rid: 'SV-220313r395691_rule'
  tag stig_id: 'O121-P3-006200'
  tag gtitle: 'SRG-APP-000080-DB-000063'
  tag fix_id: 'F-22020r392071_fix'
  tag 'documentable'
  tag legacy: ['SV-76377', 'V-61887']
  tag cci: ['CCI-000166']
  tag nist: ['AU-10']
end
