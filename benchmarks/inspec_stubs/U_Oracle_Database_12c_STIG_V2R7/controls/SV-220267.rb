control 'SV-220267' do
  title 'The DBMS must provide audit record generation capability for organization-defined auditable events within the database.'
  desc 'Audit records can be generated from various components within the information system. (e.g., network interface, hard disk, modem, etc.). From an application perspective, certain specific application functionalities may be audited as well.

The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records (i.e., auditable events, timestamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, file names involved, and access control or flow control rules invoked).

Organizations define which application components shall provide auditable events.

The DBMS must provide auditing for the list of events defined by the organization or risk negatively impacting forensic investigations into malicious behavior in the information system. Audit records can be generated from various components within the information system, such as network interfaces, hard disks, modems, etc. From an application perspective, certain specific application functionalities may be audited, as well.

The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records (i.e., auditable events, timestamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, file names involved, and access control or flow control rules invoked).

Organizations may define the organizational personnel accountable for determining which application components shall provide auditable events.

Auditing provides accountability for changes made to the DBMS configuration or its objects and data. It provides a means to discover suspicious activity and unauthorized changes. Without auditing, a compromise may go undetected and without a means to determine accountability.

The Department of Defense has established the following as the minimum set of auditable events. Most can be audited via Oracle settings; some - marked here with an asterisk - cannot, and may require OS settings.
- Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g. classification levels).
- Successful and unsuccessful logon attempts, privileged activities or other system level access
- Starting and ending time for user access to the system, concurrent logons from different workstations.
- Successful and unsuccessful accesses to objects.
- All program initiations.
- *All direct access to the information system.
- All account creations, modifications, disabling, and terminations.
- *All kernel module loads, unloads, and restarts.'
  desc 'check', %q(Verify, using vendor and system documentation if necessary, that the DBMS is configured to use Oracle's auditing features, or that a third-party product or custom code is deployed and configured to satisfy this requirement.

If a third-party product or custom code is used, compare its current configuration with the audit requirements. If any of the requirements is not covered by the configuration, this is a finding.

The remainder of this Check is applicable specifically where Oracle auditing is in use.

If Standard Auditing is used:
To see if Oracle is configured to capture audit data, enter the following SQL*Plus command:
SHOW PARAMETER AUDIT_TRAIL
or the following SQL query:
SELECT * FROM SYS.V$PARAMETER WHERE NAME = 'audit_trail';
If Oracle returns the value 'NONE', this is a finding.

To confirm that Oracle audit is capturing information on the required events, review the contents of the SYS.AUD$ table or the audit file, whichever is in use. If auditable events are not listed, this is a finding.

If Unified Auditing is used:
To see if Oracle is configured to capture audit data, enter the following SQL*Plus command:
SELECT * FROM V$OPTION WHERE PARAMETER = 'Unified Auditing';
If Oracle returns a value something other than "TRUE", this is a finding.

To confirm that Oracle audit is capturing information on the required events, review the contents of the SYS.UNIFIED_AUDIT_TRAIL view. If auditable events are not listed, this is a finding.)
  desc 'fix', %q(Configure the DBMS's auditing to audit organization-defined auditable events. If preferred, use a third-party tool. The tool must provide the minimum capability to audit the required events.

If using a third-party product, proceed in accordance with the product documentation. If using Oracle's capabilities, proceed as follows.

If Standard Auditing is used:
Use this process to ensure auditable events are captured:
ALTER SYSTEM SET AUDIT_TRAIL=<audit trail type> SCOPE=SPFILE;
Audit trail type can be 'OS', 'DB', 'DB,EXTENDED', 'XML' or 'XML,EXTENDED'.
After executing this statement, it may be necessary to shut down and restart the Oracle database.

If the site-specific audit requirements are not covered by the default audit options, deploy and configure Fine-Grained Auditing.  For details, refer to Oracle documentation at the locations below.

If Unified Auditing is used:
Use this process to ensure auditable events are captured:
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

If the site-specific audit requirements are not covered by the default audit options, deploy and configure Fine-Grained Auditing.  For details, refer to Oracle documentation at the locations above.)
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-21982r836887_chk'
  tag severity: 'medium'
  tag gid: 'V-220267'
  tag rid: 'SV-220267r879559_rule'
  tag stig_id: 'O121-C2-006800'
  tag gtitle: 'SRG-APP-000089-DB-000064'
  tag fix_id: 'F-21974r391933_fix'
  tag 'documentable'
  tag legacy: ['SV-76111', 'V-61621']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
